using FluentValidation;

namespace BuildingBlocks.Entities;

public interface IAggregate<T> : IAggregate, IEntity where T : IValidator, new() { }

public interface IAggregate : IEntity
{
    IReadOnlyList<IDomainEvent> DomainEvents { get; }
    IDomainEvent[] ClearDomainEvents();
}
