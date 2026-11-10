using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;

namespace SafeVault.Tests;

public sealed class SecurityTests
{
    private VaultFactory _app = null!;

    [OneTimeSetUp]
    public void Start() => _app = new VaultFactory();

    [OneTimeTearDown]
    public async Task Stop() => await _app.DisposeAsync();

    [Test]
    public async Task AnonymousUserCannotOpenTheVault()
    {
        using var client = _app.CreateBrowser();
        using var response = await client.GetAsync("/vault");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.ToString(), Does.StartWith("https://localhost/login"));
    }

    [Test]
    public async Task RegistrationRejectsAnInvalidUsername()
    {
        using var client = _app.CreateBrowser();
        using var response = await PostForm(client, "/register", new()
        {
            ["username"] = "<invalid-user>", ["email"] = "test@example.test", ["password"] = NewPassword()
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Not.Contain("<invalid-user>"));
    }

    [Test]
    public async Task InvalidPasswordDoesNotAuthenticate()
    {
        using var client = _app.CreateBrowser();
        var member = await Register(client);
        using var response = await PostForm(client, "/login", new()
        {
            ["username"] = member.Name, ["password"] = NewPassword()
        });
        using var vault = await client.GetAsync("/vault");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(vault.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task AdminRouteAllowsAdminAndForbidsMember()
    {
        using var memberClient = _app.CreateBrowser();
        var member = await Register(memberClient);
        await SignIn(memberClient, member.Name, member.Password);
        using var denied = await memberClient.GetAsync("/admin");
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

        using var adminClient = _app.CreateBrowser();
        await SignIn(adminClient, VaultFactory.Admin, _app.AdminPassword);
        using var allowed = await adminClient.GetAsync("/admin");
        Assert.That(allowed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task UsernameLookupTreatsSqlMetacharactersAsText()
    {
        using var client = _app.CreateBrowser();
        await SignIn(client, VaultFactory.Admin, _app.AdminPassword);
        var legitimate = await client.GetStringAsync($"/admin?username={VaultFactory.Admin}");
        Assert.That(legitimate, Does.Contain($"Found: {VaultFactory.Admin}"));

        var query = Uri.EscapeDataString("O'Reilly");
        var response = await client.GetStringAsync($"/admin?username={query}");
        Assert.That(response, Does.Contain("No match."));
        Assert.That(response, Does.Not.Contain("Found:"));
    }

    [Test]
    public async Task NotesAreEncodedAndIsolatedByOwner()
    {
        using var client = _app.CreateBrowser();
        var member = await Register(client);
        await SignIn(client, member.Name, member.Password);
        const string markup = "<em>Private note</em>";
        using var created = await PostForm(client, "/vault", new() { ["text"] = markup });
        Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var result = await client.GetStringAsync("/vault");
        Assert.That(result, Does.Not.Contain(markup));
        Assert.That(result, Does.Contain("&lt;em&gt;Private note&lt;/em&gt;"));

        using var otherClient = _app.CreateBrowser();
        var other = await Register(otherClient);
        await SignIn(otherClient, other.Name, other.Password);
        Assert.That(await otherClient.GetStringAsync("/vault"), Does.Not.Contain("Private note"));
    }

    [Test]
    public async Task PostWithoutAntiforgeryTokenIsRejected()
    {
        using var client = _app.CreateBrowser();
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["username"] = "anyone" });
        using var response = await client.PostAsync("/login", form);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task LoginPostHasARequestRateLimit()
    {
        await using var isolatedApp = new VaultFactory();
        using var client = isolatedApp.CreateBrowser();
        for (var request = 0; request < 15; request++)
        {
            using var form = new FormUrlEncodedContent([]);
            using var response = await client.PostAsync("/login", form);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        using var extraForm = new FormUrlEncodedContent([]);
        using var limited = await client.PostAsync("/login", extraForm);
        Assert.That(limited.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
    }

    private static string NewPassword() => $"T!7z{Guid.NewGuid():N}";

    private static async Task<(string Name, string Password)> Register(HttpClient client)
    {
        var name = "u" + Guid.NewGuid().ToString("N")[..16];
        var password = NewPassword();
        using var response = await PostForm(client, "/register", new()
        {
            ["username"] = name, ["email"] = $"{name}@example.test", ["password"] = password
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.OriginalString, Is.EqualTo("/login"));
        return (name, password);
    }

    private static async Task SignIn(HttpClient client, string name, string password)
    {
        using var response = await PostForm(client, "/login", new() { ["username"] = name, ["password"] = password });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.OriginalString, Is.EqualTo("/vault"));
    }

    private static async Task<HttpResponseMessage> PostForm(HttpClient client, string path, Dictionary<string, string> fields)
    {
        var html = await client.GetStringAsync(path);
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"");
        Assert.That(token.Success, Is.True, "Form must expose an antiforgery token");
        fields["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value);
        using var form = new FormUrlEncodedContent(fields);
        return await client.PostAsync(path, form);
    }

    private sealed class VaultFactory : WebApplicationFactory<Program>
    {
        public const string Admin = "test_admin";
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("safevault-tests-");
        public string AdminPassword { get; } = NewPassword();

        public HttpClient CreateBrowser() => CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services => services.AddDataProtection().UseEphemeralDataProtectionProvider());
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Vault"] = $"Data Source={Path.Combine(_directory.FullName, "test.db")};Pooling=False",
                ["SafeVault:AdminUsername"] = Admin,
                ["SafeVault:AdminEmail"] = "admin@example.test",
                ["SafeVault:AdminPassword"] = AdminPassword
            }));
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            foreach (var file in _directory.EnumerateFiles()) file.Delete();
            _directory.Delete();
        }
    }
}
