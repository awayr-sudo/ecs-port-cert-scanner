// node native promisify
const util = require("util");

class Master {
  db = null;
  tableName = null;

  constructor(db) {
    this.db = db;
  }

  async all() {
    let query = util.promisify(this.db.query).bind(this.db);
    var sql = this.db.format(
      "SELECT * FROM " + this.tableName + " where status = ?",
      [1]
    );
    let data = null;

    return await query(sql);
  }

  async find(cols, where) {
    // Return a new promise
    return new Promise((resolve, reject) => {
      let whereClause = [];
      let sqlCrit = [];

      Object.keys(where).map((item) => {
        sqlCrit.push("?? = ?");
        whereClause.push(item);
        whereClause.push(where[item]);
      });
      let crit = sqlCrit.length > 0 ? sqlCrit.join(" AND ") : "";

      // Create the sql query (this uses placeholders)
      // Hard coded values don't need to be placeholders but just for example:
      let sql = "SELECT ?? FROM ??  WHERE " + crit + " LIMIT 1";
      // Query the database replacing the ?? and ? with actual data
      this.db.query(
        sql,
        [cols, this.tableName, ...whereClause],
        function (err, result) {
          if (err) {
            console.log("my error", err);
            reject(err);
          }
          resolve(result[0]);
        }
      );
    });
  }

  async save(data, whereClause) {
    return new Promise(async (resolve, reject) => {
      let info;
      let checkExist = await this.exists(whereClause);
      console.log("check exists", checkExist);
      if (!checkExist) {
        console.log("it doesnot exists");
        info = this.create(data);
      } else {
        console.log("it exists");
        info = this.update(data, whereClause);
      }
      if (info) {
        info
          .then(function (result) {
            console.log("[inside save] The result is:", result);
            resolve(result);
          })
          .catch(function (err) {
            console.log("There was an error:", err);
            reject(err);
          });
      }
    });
  }

  async create(data) {
    const sql = "INSERT INTO " + this.tableName + " SET ?";

    return new Promise(async (resolve, reject) => {
      console.log("data insert", data);
      let q = this.db.query(sql, data, (err, result) => {
        // this.db.release();
        if (err) {
          throw err;
          console.log("my error", err);
          reject(err);
          // if (err.errno == 1062) {
          //     return false;
          // } else {
          //     reject(err);
          // }
        }
        console.log("resutl inserter", result);
        resolve(result);
      });
    });
  }

  async update(data, where) {
    return new Promise(async (resolve, reject) => {
      let whereClause = [];
      let sqlCrit = [];

      Object.keys(where).map((item) => {
        sqlCrit.push("?? = ?");
        whereClause.push(item);
        whereClause.push(where[item]);
      });
      let crit = sqlCrit.length > 0 ? sqlCrit.join(" AND ") : "";
      const sql = "UPDATE " + this.tableName + " SET ? WHERE " + crit;

      this.db.query(sql, [data, ...whereClause], (err, result) => {
        // this.db.release();
        if (err) {
          reject(err);
          // if (err.errno == 1062) {
          //     return false;
          // } else {
          //     reject(err);
          // }
        }
        resolve(result);
      });
    });
  }

  async exists(where) {
    // Return a new promise
    return new Promise((resolve) => {
      let whereClause = [];
      let sqlCrit = [];

      Object.keys(where).map((item) => {
        sqlCrit.push("?? = ?");
        whereClause.push(item);
        whereClause.push(where[item]);
      });
      let crit = sqlCrit.length > 0 ? sqlCrit.join(" AND ") : "";

      // Create the sql query (this uses placeholders)
      // Hard coded values don't need to be placeholders but just for example:
      let sql = "SELECT 1 FROM ??  WHERE " + crit;
      // Query the database replacing the ?? and ? with actual data
      this.db.query(
        sql,
        [this.tableName, ...whereClause],
        function (error, result, field) {
          // this.db.release();
          // Result will either be undefined or a row.
          // Convert it to a boolean and return it.
          console.log("result exist", result);
          let returnR = result && result.length > 0;
          resolve(returnR);
        }
      );
    });
  }
}

module.exports = Master;
