using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public sealed class VaultDb(DbContextOptions<VaultDb> options) : IdentityDbContext<IdentityUser>(options)
{
    public DbSet<VaultNote> Notes => Set<VaultNote>();

    public async Task<string?> FindUsernameAsync(string normalizedName, CancellationToken cancellationToken)
    {
        // EF Core sends the interpolated value as a database parameter.
        return await Database.SqlQuery<string>(
            $"SELECT UserName AS Value FROM AspNetUsers WHERE NormalizedUserName = {normalizedName}")
            .SingleOrDefaultAsync(cancellationToken);
    }
}

public sealed class VaultNote
{
    public int Id { get; set; }
    public required string OwnerId { get; init; }
    public required string Text { get; init; }
}
