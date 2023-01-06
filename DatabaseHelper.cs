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
  public static class DatabaseHelper
  {
    public static void ConfigureIdentityOptions(IdentityOptions options)
    {
      // Password settings.
      options.Password.RequireDigit = true;
      options.Password.RequireLowercase = true;
      options.Password.RequireUppercase = true;
      options.Password.RequireNonAlphanumeric = false;
      options.Password.RequiredLength = 12;
      // options.Password.RequiredUniqueChars = 1;

      // Lockout settings.
      // options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
      // options.Lockout.MaxFailedAccessAttempts = 5;
      // options.Lockout.AllowedForNewUsers = true;

      // User settings.
      options.User.AllowedUserNameCharacters =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
      options.User.RequireUniqueEmail = true;
    }

    public static string GeneratePassword(int length = 16, IEnumerable<char>? characterSet = null)
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