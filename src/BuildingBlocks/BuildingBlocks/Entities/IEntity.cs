﻿namespace BuildingBlocks.Entities;

public interface IEntity
{
    public Guid Id { get; set; }
    public DateTime? CreatedAt { get; set; }
    public string CreatedBy { get; set; }
    public DateTime? LastModified { get; set; }
    public string LastModifiedBy { get; set; }
    public bool Removed { get; set; }
    public string RemovedBy { get; set; }
}
