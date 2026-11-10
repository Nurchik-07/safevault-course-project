using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024);
builder.Services.AddDbContext<VaultDb>(options => options.UseSqlite(
    builder.Configuration.GetConnectionString("Vault") ?? "Data Source=safevault.db"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.Password.RequiredLength = 12;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
}).AddEntityFrameworkStores<VaultDb>();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = false;
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});
builder.Services.AddAntiforgery(options => options.Cookie.SecurePolicy = CookieSecurePolicy.Always);
builder.Services.AddAuthorization(options => options.AddPolicy("Admins", policy =>
    policy.RequireAuthenticatedUser().RequireRole("Admin")));
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("login-ip", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 15,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});

var app = builder.Build();
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Cache-Control"] = "no-store";
    await next();
});
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

await InitializeVaultAsync(app.Services, app.Configuration);

app.MapGet("/", () => Results.Redirect("/vault"));
app.MapGet("/register", (HttpContext context, IAntiforgery csrf) => Page("Register",
    Form(context, csrf, "/register", """
        <label>Username <input name="username" required maxlength="32" autocomplete="username"></label>
        <label>Email <input name="email" required type="email" maxlength="100" autocomplete="email"></label>
        <label>Password <input name="password" required type="password" minlength="12" maxlength="128" autocomplete="new-password"></label>
        <button>Register</button>
        """)));
app.MapPost("/register", async (HttpContext context, IAntiforgery csrf, VaultDb db, UserManager<IdentityUser> users) =>
{
    var form = await ReadFormAsync(context, csrf);
    if (form is null) return Results.BadRequest();
    if (form["username"].Count != 1 || form["email"].Count != 1 || form["password"].Count != 1)
        return Page("Invalid registration", "<p>Supply one username, email, and password.</p>", 400);
    var name = form["username"].ToString().Trim();
    var email = form["email"].ToString().Trim();
    var password = form["password"].ToString();
    if (!Regex.IsMatch(name, @"\A[A-Za-z0-9_.-]{3,32}\z") || email.Length is < 3 or > 100 ||
        !new EmailAddressAttribute().IsValid(email) || password.Length is < 12 or > 128)
        return Page("Invalid registration", "<p>Check the username, email, and password requirements.</p>", 400);

    await using var transaction = await db.Database.BeginTransactionAsync(context.RequestAborted);
    var user = new IdentityUser { UserName = name, Email = email };
    var result = await users.CreateAsync(user, password);
    if (!result.Succeeded || !(await users.AddToRoleAsync(user, "Member")).Succeeded)
        return Page("Registration unsuccessful", "<p>Check your details and password complexity.</p>", 400);

    await transaction.CommitAsync(context.RequestAborted);
    return Results.Redirect("/login");
});

app.MapGet("/login", (HttpContext context, IAntiforgery csrf) => Page("Sign in",
    Form(context, csrf, "/login", """
        <label>Username <input name="username" required maxlength="32" autocomplete="username"></label>
        <label>Password <input name="password" type="password" required maxlength="128" autocomplete="current-password"></label>
        <button>Sign in</button>
        """)));
app.MapPost("/login", async (HttpContext context, IAntiforgery csrf, SignInManager<IdentityUser> signIn) =>
{
    var form = await ReadFormAsync(context, csrf);
    if (form is null) return Results.BadRequest();
    var name = form["username"].ToString().Trim();
    var password = form["password"].ToString();
    if (name.Length is < 3 or > 32 || password.Length is < 1 or > 128)
        return Page("Sign in failed", "<p>Invalid credentials or account temporarily locked.</p>", 401);
    var result = await signIn.PasswordSignInAsync(name, password, isPersistent: false, lockoutOnFailure: true);
    return result.Succeeded ? Results.Redirect("/vault") :
        Page("Sign in failed", "<p>Invalid credentials or account temporarily locked.</p>", 401);
}).RequireRateLimiting("login-ip");

app.MapGet("/vault", async (HttpContext context, IAntiforgery csrf, VaultDb db) =>
{
    var owner = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var notes = await db.Notes.Where(note => note.OwnerId == owner).OrderByDescending(note => note.Id)
        .Take(50).Select(note => note.Text).ToListAsync(context.RequestAborted);
    var list = string.Concat(notes.Select(note => $"<li>{Encode(note)}</li>"));
    return Page("My notes", "<ul>" + list + "</ul>" +
        Form(context, csrf, "/vault", "<label>Note <textarea name=\"text\" required maxlength=\"500\"></textarea></label><button>Save</button>") +
        Form(context, csrf, "/logout", "<button>Sign out</button>"));
}).RequireAuthorization();
app.MapPost("/vault", async (HttpContext context, IAntiforgery csrf, VaultDb db) =>
{
    var form = await ReadFormAsync(context, csrf);
    if (form is null) return Results.BadRequest();
    var text = form["text"].ToString().Trim();
    if (text.Length is < 1 or > 500) return Results.BadRequest();
    db.Notes.Add(new VaultNote { OwnerId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)!, Text = text });
    await db.SaveChangesAsync(context.RequestAborted);
    return Results.Redirect("/vault");
}).RequireAuthorization();

app.MapPost("/logout", async (HttpContext context, IAntiforgery csrf, SignInManager<IdentityUser> signIn) =>
{
    if (await ReadFormAsync(context, csrf) is null) return Results.BadRequest();
    await signIn.SignOutAsync();
    return Results.Redirect("/login");
}).RequireAuthorization();

app.MapGet("/admin", async (HttpContext context, VaultDb db, ILookupNormalizer normalizer) =>
{
    var input = context.Request.Query["username"].ToString();
    if (input.Length > 100) return Results.BadRequest();
    var name = input.Length == 0 ? null : await db.FindUsernameAsync(
        normalizer.NormalizeName(input)!, context.RequestAborted);
    return Page("Admin user lookup", """
        <form method="get"><label>Username <input name="username" maxlength="100"></label><button>Search</button></form>
        """ + (input.Length == 0 ? "" : name is null ? "<p>No match.</p>" : $"<p>Found: {Encode(name)}</p>"));
}).RequireAuthorization("Admins");

app.Run();

static string Encode(string value) => HtmlEncoder.Default.Encode(value);

static IResult Page(string title, string content, int status = 200) => Results.Content($$"""
    <!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{Encode(title)}} | SafeVault</title></head>
    <body><nav><a href="/vault">Vault</a> · <a href="/login">Sign in</a> · <a href="/register">Register</a> · <a href="/admin">Admin</a></nav>
    <main><h1>{{Encode(title)}}</h1>{{content}}</main></body></html>
    """, "text/html; charset=utf-8", statusCode: status);

static string Form(HttpContext context, IAntiforgery csrf, string action, string fields)
{
    var tokens = csrf.GetAndStoreTokens(context);
    return $"<form method=\"post\" action=\"{Encode(action)}\"><input type=\"hidden\" name=\"{Encode(tokens.FormFieldName)}\" value=\"{Encode(tokens.RequestToken!)}\">{fields}</form>";
}

static async Task<IFormCollection?> ReadFormAsync(HttpContext context, IAntiforgery csrf)
{
    if (!context.Request.HasFormContentType) return null;
    try
    {
        await csrf.ValidateRequestAsync(context);
        return await context.Request.ReadFormAsync(context.RequestAborted);
    }
    catch (AntiforgeryValidationException)
    {
        return null;
    }
}

static async Task InitializeVaultAsync(IServiceProvider services, IConfiguration configuration)
{
    await using var scope = services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<VaultDb>();
    await db.Database.EnsureCreatedAsync();
    var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Member", "Admin" })
        if (!await roles.RoleExistsAsync(role) && !(await roles.CreateAsync(new IdentityRole(role))).Succeeded)
            throw new InvalidOperationException("Could not initialize vault roles.");

    var name = configuration["SafeVault:AdminUsername"];
    var email = configuration["SafeVault:AdminEmail"];
    var password = configuration["SafeVault:AdminPassword"];
    if (name is null && email is null && password is null) return;
    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        throw new InvalidOperationException("Set all three SafeVault admin settings before bootstrapping.");

    var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var existing = await users.FindByNameAsync(name);
    if (existing is not null)
    {
        if (!await users.IsInRoleAsync(existing, "Admin"))
            throw new InvalidOperationException("The configured administrator username already belongs to a member.");
        return;
    }

    await using var transaction = await db.Database.BeginTransactionAsync();
    var admin = new IdentityUser { UserName = name, Email = email };
    if (!(await users.CreateAsync(admin, password)).Succeeded || !(await users.AddToRoleAsync(admin, "Admin")).Succeeded)
        throw new InvalidOperationException("Could not bootstrap the administrator. Check the configured credentials.");
    await transaction.CommitAsync();
}

public partial class Program { }
