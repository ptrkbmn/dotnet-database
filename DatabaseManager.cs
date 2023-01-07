using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace pbdev.Database
{
  public partial class Roles
  {
    public const string Administrator = "Administrator";
    public const string User = "User";

    public static readonly string[] AllRoles = new[] { Administrator, User };

    /// <summary>
    /// Checks if the given role name is a valid role name. It also returns the
    /// role name converted to uppercase.
    /// </summary>
    public static string CheckReturn(string? role)
    {
      if (String.IsNullOrEmpty(role))
        throw new Exception("No role name given");

      string roleUpper = role.ToUpperInvariant();
      if (!AllRoles.Contains(roleUpper))
        throw new Exception("Invalid role name");

      return roleUpper;
    }
  }

  class CommonOptions
  {
    [Option("dbtype", Required = true, HelpText = "Database type (mysql or sqlite)")]
    public string DBType { get; set; } = default!;

    [Option("dbserver", HelpText = "Database server", Default = "localhost", SetName = "sql")]
    public string? DBServer { get; set; }

    [Option("dbname", Required = true, HelpText = "Database name ", SetName = "sql")]
    public string? DBName { get; set; }

    [Option("dbuser", HelpText = "Database user", SetName = "sql")]
    public string? DBUser { get; set; }

    [Option("dbpassword", HelpText = "Database user password", SetName = "sql")]
    public string? DBPassword { get; set; }

    [Option("dbfile", Required = true, HelpText = "Database file", SetName = "sqlite")]
    public string? DBFile { get; set; }
  }

  [Verb("create-user")]
  class CreateUserOptions : CommonOptions
  {
    [Option("email", Required = true, HelpText = "Email address of the new user")]
    public string Email { get; set; } = default!;

    [Option("role", HelpText = "The name of the role the user is added to")]
    public string Role { get; set; } = Roles.User;
  }

  [Verb("reset-user")]
  class ResetUserOptions : CommonOptions
  {
    [Option("password", Required = true, HelpText = "Email address of the user")]
    public string? UserEmail { get; set; }
  }

  [Verb("db")]
  class DatabaseOptions : CommonOptions
  {
    [Option("migrate", HelpText = "Perform database migrations")]
    public bool Migrate { get; set; }

    [Option("init", HelpText = "Initialize roles and other stuff")]
    public bool Initialize { get; set; }
  }

  public class DatabaseManager<TDbContext, TIdentityUser>
    where TDbContext : DbContext where TIdentityUser : IdentityUser
  {
    public Action<IdentityOptions>? CustomIdentityOptionsAction { get; set; }

    public void ParseArguments(string[] args)
    {
      try
      {
        Parser.Default.ParseArguments<CreateUserOptions, ResetUserOptions, DatabaseOptions>(args)
        .WithParsed<CreateUserOptions>(o =>
        {
          var serviceProvider = GetServiceProvider(o);

          if (!String.IsNullOrEmpty(o.Email))
          {
            var userManager = serviceProvider.GetService<UserManager<TIdentityUser>>();
            if (userManager == null)
              throw new Exception("Unable to resolve UserManager...");

            string role = Roles.CheckReturn(o.Role);
            string password = DatabaseHelper.GeneratePassword();

            var user = (TIdentityUser)Activator.CreateInstance(typeof(TIdentityUser))!;
            user.UserName = o.Email;
            user.Email = o.Email;
            var userResult = userManager.CreateAsync(user, password).Result;
            if (userResult.Succeeded)
            {
              Console.WriteLine("New user created!");
              Console.WriteLine("User name: {0}", o.Email);
              Console.WriteLine("Password:  {0}", password);
            }
            else
            {
              Console.WriteLine("Errors occurred (create user)!");
              foreach (var e in userResult.Errors)
                Console.WriteLine(e.Description);
            }

            var roleResult = userManager.AddToRoleAsync(user, role).Result;
            if (roleResult.Succeeded)
            {
              Console.WriteLine("User added ro role {0}!", role);
            }
            else
            {
              Console.WriteLine("Errors occurred (add to role)!");
              foreach (var e in userResult.Errors)
                Console.WriteLine(e.Description);
            }
          }
        })
        .WithParsed<ResetUserOptions>(o =>
        {
          var serviceProvider = GetServiceProvider(o);
          if (!String.IsNullOrEmpty(o.UserEmail))
          {
            var userManager = serviceProvider.GetService<UserManager<TIdentityUser>>();
            if (userManager == null)
              throw new Exception("Unable to resolve UserManager...");

            var user = userManager.FindByNameAsync(o.UserEmail).Result;
            if (user != null)
            {
              string resetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;
              string newPassword = DatabaseHelper.GeneratePassword();
              var result = userManager.ResetPasswordAsync(user, resetToken, newPassword).Result;
              if (result.Succeeded)
              {
                Console.WriteLine("Password for {0} reset!", o.UserEmail);
                Console.WriteLine("New password: {0}", newPassword);
              }
              else
              {
                Console.WriteLine("Errors occurred!");
                foreach (var e in result.Errors)
                  Console.WriteLine(e.Description);
              }
            }
            else
            {
              Console.WriteLine("User {0} not found!", o.UserEmail);
            }
          }
        })
        .WithParsed<DatabaseOptions>(o =>
        {
          var serviceProvider = GetServiceProvider(o);
          var context = serviceProvider.GetRequiredService<TDbContext>();

          if (o.Migrate)
          {
            context.Database.Migrate();
          }
          else if (o.Initialize)
          {
            var idDbContext = context as IdentityDbContext<TIdentityUser>;
            if (idDbContext != null)
            {
              var roles = idDbContext.Roles.ToList();
              if (!roles.Any())
              {
                idDbContext.Roles.Add(new IdentityRole(Roles.Administrator) { NormalizedName = Roles.Administrator.ToUpperInvariant() });
                idDbContext.Roles.Add(new IdentityRole(Roles.User) { NormalizedName = Roles.User.ToUpperInvariant() });
                idDbContext.SaveChanges();
                Console.WriteLine("Initialized roles table");
              }
              else
              {
                Console.WriteLine("Roles table already initialized");
              }
            }
          }
          else
          {
            Console.WriteLine("Invalid parameters");
          }
        });
      }
      catch (Exception e)
      {
        Console.WriteLine(e.Message);
      }
    }

    private IServiceProvider GetServiceProvider(CommonOptions o)
    {
      var services = new ServiceCollection();
      services.AddDbContextPool<TDbContext>(options =>
      {
        switch (o.DBType)
        {
          case "sqlite":
            {
              options.UseSqlite("Filename=" + o.DBFile);
              break;
            }
          case "mysql":
            {
              string connectionString = String.Format("server={0};user id={1};password={2};database={3}", o.DBServer, o.DBUser, o.DBPassword, o.DBName);
              options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString), options => { });
              break;
            }
          default:
            {
              throw new NotSupportedException(String.Format("The database type {0} is not supported!", o.DBType));
            }
        }
      });
      services.AddLogging();
      services.AddIdentity<TIdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<TDbContext>()
        .AddDefaultTokenProviders();

      services.AddScoped(p => (TDbContext)Activator.CreateInstance(typeof(TDbContext), p.GetService<DbContextOptions<TDbContext>>())!);

      if (CustomIdentityOptionsAction != null)
        services.Configure<IdentityOptions>(o => CustomIdentityOptionsAction.Invoke(o));

      return services.BuildServiceProvider();
    }

  }

  /// <summary>
  /// DatabaseManager with the default IdentityUser type.
  /// </summary>
  public class DatabaseManager<TDbContext> : DatabaseManager<TDbContext, IdentityUser>
    where TDbContext : DbContext
  { }
}
