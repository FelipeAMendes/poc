using MongoDB.Bson.Serialization.Attributes;

namespace MyResume.Core.Shared.Entities.Interfaces;

public interface IBaseEntityNoSql
{
    [BsonId]
    Guid Id { get; set; }
    DateTimeOffset CreatedDate { get; set; }
    bool Removed { get; set; }
}
