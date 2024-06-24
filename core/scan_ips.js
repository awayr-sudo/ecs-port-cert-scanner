// Import the util module
const util = require("util");
const Logs = require("./logs");
const Master = require("./master");

class ScanIps extends Master {
  tableName = "scan_ips";

  async updateOs(os, status, isProcessed, data) {
    const sql =
      "UPDATE " +
      this.tableName +
      " SET os=?, status=?,is_processed=?, updated_at=? WHERE id = ? and scan_id = ?";
    console.log("statuses OS", os, status, data);
    return new Promise(async (resolve, reject) => {
      this.db.query(
        sql,
        [os, status, isProcessed, new Date(), data.ipId, data.scanId],
        (err, result) => {
          if (err) {
            reject(err);
            // if (err.errno == 1062) {
            //     return false;
            // } else {
            //     reject(err);
            // }
          }
          resolve(result);
        }
      );
    });
  }

  // ips process check
  async checkIpsProcessed(data) {
    return new Promise(async (resolve, reject) => {
      const sql =
        "SELECT 1 as 'stil_pending' FROM " +
        this.tableName +
        " WHERE  (is_processed is null OR is_processed = 0)  AND scan_id = ?";
      console.log("statuses", data, sql);

      this.db.query(sql, [data.scanId], (err, result) => {
        if (err) {
          console.log("log reject issue");
          reject(err);
          // if (err.errno == 1062) {
          //     return false;
          // } else {
          //     reject(err);
          // }
        }
        let isSomethingPending = result[0]?.stil_pending;
        if (!isSomethingPending) {
          console.log("i am here ");
          this.db.query(
            "UPDATE scans_selected_services SET service_status=3 WHERE service_id=? AND scan_id = ?",
            [data.serviceId, data.scanId],
            (err, result) => {
              if (err) {
                console.log("unable to update service status", err);
                reject(err);
                // if (err.errno == 1062) {
                //     return false;
                // } else {
                //     reject(err);
                // }
              }
              console.log("result service", result);
              let logs = new Logs(this.db);
              let msg = util.format(
                "Asset discovery scanning completed for %s",
                data.scanData.scan_input || ""
              );
              let logData = {
                scan_id: data.scanId,
                service_id: data.serviceId,
                scan_service_id: data.scanServiceId,
                log: msg,
                created_at: new Date(),
                updated_at: new Date(),
              };
              console.log("log", logData);
              let whereClause = {
                scan_id: data.scanId,
                service_id: data.serviceId,
              };
              let info = logs
                .save(logData, whereClause)
                .then(function (result) {
                  console.log("The log result is:", result?.message);
                  resolve(isSomethingPending); //processed
                })
                .catch(function (err) {
                  console.log("There was an error while generating log:", err);
                  reject(err);
                });
            }
          );
        } else {
          console.log("we cannot mark it done as some ips are pending");
          resolve(isSomethingPending);
        }
      });
    });
  }
}
module.exports = ScanIps;
