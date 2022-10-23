using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace pbdev.Database.Entities;

public interface INameEntity
{
  string Name { get; }
}

public interface INameRevEntity : INameEntity
{
  string NameRev { get; }
}