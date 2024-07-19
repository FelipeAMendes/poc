using MongoDB.Bson.Serialization.Attributes;

namespace BuildingBlocks.Entities;

public interface IBaseEntityNoSql
{
    [BsonId]
    Guid Id { get; set; }
    DateTimeOffset CreatedIn { get; set; }
    bool Removed { get; set; }
}

public abstract class BaseEntityNoSql : IBaseEntityNoSql
{
    protected BaseEntityNoSql()
    {
        CreatedIn = DateTimeOffset.Now;
    }

    [BsonId]
    public Guid Id { get; set; }
    public DateTimeOffset CreatedIn { get; set; }
    public bool Removed { get; set; }

    public void Remove()
    {
        Removed = true;
    }

    protected void SetCreatedDate(DateTimeOffset createdIn)
    {
        CreatedIn = createdIn;
    }
}