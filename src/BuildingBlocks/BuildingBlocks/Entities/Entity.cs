using BuildingBlocks.Validations;
using FluentValidation;

namespace BuildingBlocks.Entities;

public abstract class Entity<T> : BaseValidation<T>, IEntity where T : IValidator, new()
{
    public Guid Id { get; set; }
    public DateTime? CreatedAt { get; set; }
    public string CreatedBy { get; set; }
    public DateTime? LastModified { get; set; }
    public string LastModifiedBy { get; set; }
    public bool Removed { get; set; }
    public string RemovedBy { get; set; }
}
