using FluentValidation;

namespace BuildingBlocks.Entities;

public abstract class Aggregate<T> : Entity<T>, IAggregate<T> where T : IValidator, new()
{
    private readonly List<IDomainEvent> _domainEvents = [];
    public IReadOnlyList<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    public void AddDomainEvent(IDomainEvent domainEvent)
    {
        _domainEvents.Add(domainEvent);
    }

    public IDomainEvent[] ClearDomainEvents()
    {
        IDomainEvent[] dequeuedEvents = [.. _domainEvents];

        _domainEvents.Clear();

        return dequeuedEvents;
    }
}
