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
using Microsoft.Extensions.DependencyInjection;

namespace pbdev.Database
{
  class CommonOptions
  {
    [Option("dbserver", HelpText = "Database Server", Default = "localhost")]
    public string DBServer { get; set; }

    [Option("dbname", Required = true, HelpText = "Database name")]
    public string DBName { get; set; }

    [Option("dbuser", Required = true, HelpText = "Database user")]
    public string DBUser { get; set; }

    [Option("dbpassword", Required = true, HelpText = "Database user password")]
    public string DBPassword { get; set; }
  }

  [Verb("create")]
  class CreateOptions : CommonOptions
  {
    [Option("user", Required = true, HelpText = "Email address of the new user", SetName = "user")]
    public string UserEmail { get; set; }

    [Option("role", Required = true, HelpText = "Name of the new role", SetName = "role")]
    public string Role { get; set; }
  }

  [Verb("reset")]
  class ResetOptions : CommonOptions
  {
    [Option("password", Required = true, HelpText = "Email address of the user")]
    public string UserEmail { get; set; }
  }

  [Verb("db")]
  class DatabaseOptions : CommonOptions
  {
    [Option("migrate", HelpText = "Perform database migrations", SetName = "migrate")]
    public bool Migrate { get; set; }

    [Option("init", HelpText = "Initialize roles and other stuff", SetName = "init")]
    public bool Initialize { get; set; }
  }

  public class DatabaseManager<TDbContext, TIdentityUser>
    where TDbContext : DbContext where TIdentityUser : IdentityUser
  {
    public void ParseArguments(string[] args)
    {
      try
      {
        Parser.Default.ParseArguments<CreateOptions, ResetOptions, DatabaseOptions>(args)
        .WithParsed<CreateOptions>(o =>
        {
          var serviceProvider = GetServiceProvider(o);

          if (!String.IsNullOrEmpty(o.UserEmail))
          {
            var userManager = serviceProvider.GetService<UserManager<TIdentityUser>>();

            string password = GeneratePassword();

            var user = (TIdentityUser)Activator.CreateInstance(typeof(TIdentityUser));
            user.UserName = o.UserEmail;
            user.Email = o.UserEmail;
            var result = userManager.CreateAsync(user, password).Result;
            if (result.Succeeded)
            {
              Console.WriteLine("New user created!");
              Console.WriteLine("User name: {0}", o.UserEmail);
              Console.WriteLine("Password:  {0}", password);
            }
            else
            {
              Console.WriteLine("Errors occurred!");
              foreach (var e in result.Errors)
                Console.WriteLine(e.Description);
            }
          }
        })
        .WithParsed<ResetOptions>(o =>
        {
          var serviceProvider = GetServiceProvider(o);
          if (!String.IsNullOrEmpty(o.UserEmail))
          {
            var userManager = serviceProvider.GetService<UserManager<TIdentityUser>>();
            var user = userManager.FindByNameAsync(o.UserEmail).Result;
            if (user != null)
            {
              string resetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;
              string newPassword = GeneratePassword();
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
                idDbContext.Roles.Add(new IdentityRole("Administrator") { NormalizedName = "ADMINISTRATOR" });
                idDbContext.Roles.Add(new IdentityRole("User") { NormalizedName = "USER" });
                idDbContext.SaveChanges();
                Console.WriteLine("Initialized roles table");
              }
              else
              {
                Console.WriteLine("Roles table already initialized");
              }
            }
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
      string connectionString = String.Format("server={0};user id={1};password={2};database={3}", o.DBServer, o.DBUser, o.DBPassword, o.DBName);
      var services = new ServiceCollection();
      services.AddDbContextPool<TDbContext>(options =>
      {
        options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString), options => { });
      });
      services.AddLogging();
      services.AddIdentity<TIdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<TDbContext>()
        .AddDefaultTokenProviders();

      services.AddScoped(p => (TDbContext)Activator.CreateInstance(typeof(TDbContext), p.GetService<DbContextOptions<TDbContext>>()));
      return services.BuildServiceProvider();
    }

    public static string GeneratePassword(int length = 16, IEnumerable<char> characterSet = null)
    {
      if (characterSet == null)
        characterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$%&#+-";

      var characterArray = characterSet.Distinct().ToArray();
      var bytes = new byte[length * 8];
      RandomNumberGenerator.Create().GetBytes(bytes);
      var result = new char[length];
      for (int i = 0; i < length; i++)
      {
        ulong value = BitConverter.ToUInt64(bytes, i * 8);
        result[i] = characterArray[value % (uint)characterArray.Length];
      }
      return new string(result);
    }
  }
}
