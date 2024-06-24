const Master = require("./master");

class ScanPorts extends Master {
  tableName = "scan_ports";
  async exists1(scanId, ipId, val) {
    // Return a new promise
    return new Promise((resolve) => {
      // Create the sql query (this uses placeholders)
      // Hard coded values don't need to be placeholders but just for example:
      let sql = "SELECT 1 FROM ?? WHERE ?? = ? AND ?? = ? AND ?? = ?";
      // Query the database replacing the ?? and ? with actual data
      this.db.query(
        sql,
        [this.tableName, "scan_id", scanId, "ip_id", ipId, "port", val],
        function (error, result, field) {
          // Result will either be undefined or a row.
          // Convert it to a boolean and return it.
          console.log('field', field)
          let returnR = (result && result.length > 0) || false;
          resolve(returnR);
        }
      );
    });
  }
 
}
module.exports = ScanPorts;
