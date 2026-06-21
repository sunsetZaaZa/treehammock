namespace treehammock.Rigging.Database;

using System.Data;
using System.Data.Common;
using treehammock.Rigging.Config;
using Microsoft.Extensions.Options;
using Npgsql;

public class StorageContext
{
    protected readonly DatabaseSettings _dbSettings;
    protected readonly NpgsqlDataSource _databaseInstance;

    public StorageContext(IOptions<DatabaseSettings> dbSettings)
    {
        _dbSettings = dbSettings.Value;

        var connectionString = $"Host={_dbSettings.servers}; Database={_dbSettings.database}; Username={_dbSettings.userId}; Password={_dbSettings.password};";
        NpgsqlDataSourceBuilder connection = new NpgsqlDataSourceBuilder(connectionString);
        connection.UseNodaTime();
        this._databaseInstance = connection.Build();
    }

    public virtual async Task<NpgsqlConnection> CreateConnection()
    {
        return await _databaseInstance.OpenConnectionAsync();
    }
}