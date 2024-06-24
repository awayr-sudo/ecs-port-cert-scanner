const child_process = require("child_process");
const exec = child_process.exec;
// AWS
// Load the SDK for JavaScript
var AWS = require("aws-sdk");
const fs = require("fs");
const { convertToJson } = require("./core/converter");
const IAM_USER_KEY = process.env?.IAM_USER_KEY;
const IAM_USER_SECRET = process.env?.IAM_USER_SECRET;
const BUCKET_NAME = process.env?.BUCKET_NAME;
const RESULT_FILE_PREFIX = process.env?.RESULT_FILE_PREFIX;
const CMD = process.env?.CMD;
const SCAN_ID = process.env?.SCAN_ID;
const IPS = process.env?.IPS;

const REGION = process.env?.REGION;
const SERVICE_NMAP_ID = process.env?.SERVICE_NMAP_ID;
const SCAN_SERVICE_NMAP_ID = process.env?.SCAN_SERVICE_NMAP_ID;
// const SERVICE_CERT_ID = process.env?.SERVICE_CERT_ID;
AWS.config.update({
  region: REGION,
  accessKeyId: IAM_USER_KEY,
  secretAccessKey: IAM_USER_SECRET,
});

let db = require("./core/db");
let ScanIps = require("./core/scan_ips");
const ScanPorts = require("./core/scan_ports");
const Scans = require("./core/scans");

const handleRequest = async (info) => {
  return new Promise(async (resolve, reject) => {
    if (!CMD || !info) {
      reject("Please specify a command to run as cmd");
    }
    let tmpInfo = info.trim().split("-");

    if (!SCAN_ID) {
      reject("Please specify scan id to scan");
    }

    if (!tmpInfo[1]) {
      reject("Please specify an ip to scan");
    }

    if (!tmpInfo[0]) {
      reject("Please specify an ip id to scan");
    }
    let ip = tmpInfo[1];
    let ipId = tmpInfo[0];
    let logFile = `${RESULT_FILE_PREFIX}${SCAN_ID}-${ipId}.xml`;
    let command = `${CMD} ${logFile} ${ip}`;
    console.log("command", command);
    const child = exec(
      command,
      { maxBuffer: 10 * 1024 * 1024 },
      async (error, data) => {
        if (error) {
          console.log("Error:", error);
          throw error;
        }
        // console.log("-------------------------\n");
        // console.log(data);
        // console.log("-------------------------\n");
        // Usage

        console.log("Uploading file to s3....", logFile);
        await uploadFile(logFile, ipId, resolve, reject);
        console.log("Finished");
        // resolve('process completed successfully.')
      }
    );

    // Log process stdout and stderr
    child.stdout.on("data", (data) => {
      // console.log("Response:", data);
    });

    child.stderr.on("error:", (data) => {
      console.log("Error:", data);
    });
  });
};

const uploadFile = async (fileName, ipId, resolve, reject) => {
  const fileContent = fs.readFileSync(fileName, "utf8");
  // build s3 opbject
  const s3 = new AWS.S3({
    accessKeyId: IAM_USER_KEY /* required */,
    secretAccessKey: IAM_USER_SECRET /* required */,
    Bucket: BUCKET_NAME /* required */,
  });

  const params = {
    Bucket: BUCKET_NAME,
    Key: fileName,
    Body: fileContent,
  };
  let queue = {
    scanId: SCAN_ID,
    ipId: ipId,
    fileKey: fileName,
  };
  await s3.upload(params, async (err, data) => {
    if (err) {
      console.error("Error uploading file:", err);
      reject(err);
    } else {
      // await addToQue(queue, resolve, reject); //add to que....
      await processPorts(fileContent, queue, resolve, reject); //add to que....
      console.log(`File uploaded successfully. ${data.Location}`);
    }
  });
};

const processPorts = async (data, params, resolve, reject) => {
  const { scanId, ipId, fileKey } = params;
  console.log('params', params)
  console.log("ip", ipId, scanId, fileKey);
  try {
    let scanIps = new ScanIps(db);
    let scanPorts = new ScanPorts(db);
    let scans = new Scans(db);
    const scanData = await scans.find(["id", "scan_input"], {
      id: scanId,
    });
    const scanIpData = await scanIps.find(["id", "ip_id"], {
      id: ipId,
    });
    console.log(scanIpData)
    if (scanIpData) {
      let os = null;
      let ipStatus = false;
      try {
        // const data = fs.readFileSync(fileKey, "utf8");

        const json = convertToJson(data);
        let whereData = {
          scanId: scanId,
          ipId: ipId,
          serviceId: SERVICE_NMAP_ID,
          scanServiceId: SCAN_SERVICE_NMAP_ID,
          scanData,
        };
        // console.log(json);
        if (json) {
          // console.log("dddd", xml);
          os = json?.osNmap;

          

          if (json?.openPorts) {
            ipStatus = 1;
            let openPorts = json.openPorts;
            console.log("ports", openPorts.length);
            if (openPorts.length > 300) {
              // it is masked ip
              ipStatus = -1;
            } else {
              let tpWrapCheck = openPorts.filter(function (port) {
                return (
                  port?.port * 1 >= 1 && (port?.port * 1) <= 5 &&
                  port?.service.toLowerCase().indexOf("tcpwrapped") >= 0
                );
              });
              
              if (Array.isArray(tpWrapCheck) && tpWrapCheck.length >= 5) {
                ipStatus = -1;
              }
            }

            if (openPorts.length > 0) {
              // we are going to save max 200...
              openPorts = openPorts.slice(0, 200);
            }

            for (var port of openPorts) {
              if (port?.port) {
                // console.log("port", port);

                let item = {
                  scan_id: scanId,
                  ip_id: scanIpData.ip_id,
                  scan_ip_id: scanIpData.id,
                  port: port.port,
                  protocol: port?.protocol,
                  service: port?.service,
                  tunnel: port?.tunnel,
                  product: port?.product,
                  method: port?.method,
                  version: port?.version,
                  results: JSON.stringify(port),
                };
                // building where clause from above result
                let whereClause = {
                  scan_id: item.scan_id,
                  scan_ip_id: item.scan_ip_id,
                  port: item.port,
                };
                let jobs = [];
                jobs.push(scanPorts.save(item, whereClause));

                await Promise.all(
                  jobs.map((p) =>
                    p
                      .then((res) => {
                        console.log("port scanning finished", res);
                      })
                      .catch((error) => {
                        // If the domain isn't registered, if most certainly doesn't have SPF
                        // records.
                        console.log("error while port scanning.", error);
                      })
                  )
                );
              }
            }
          }
        } else {
          console.log("Nothing to process... keep the ip status to zero `0`");
        }

        // update OS and status

        let res = await scanIps.updateOs(
          os,
          ipStatus,
          1, //is processed
          whereData
        );
        await scanIps
          .checkIpsProcessed(whereData)
          .then(function (result) {
            console.log("The result is:", result?.message);
            resolve(result);
          })
          .catch(function (err) {
            console.log("There was an error:", err);
            reject(err);
          });
      } catch (err) {
        console.log("error while processing file", err);
        reject(err);
      }
    } else {
      console.log("no ip found to process...");
      throw new Error("no ip found to process...");
    }
  } catch (err) {
    console.log("error", err);
    throw new Error("Unable to fetch the ip details...", err); // Wwhatever message you want here
  }
};

const processCertificate = async (ip) => {
  return new Promise((resolve, reject) => {
    let jsonPath = `/tmp/certificates-${ip}.json`;
    try {
      let cmd = `testssl -p -s -e -S --overwrite -oJ ${jsonPath} ${ip}`;

      const lsProcess = exec(cmd);
      lsProcess.stdout.on("data", (data) => {
        console.log(`stdout:\n${data}`);
      });
      lsProcess.stdout.on("message", function (message) {
        // handle message (a line of text from stdout, parsed as JSON)
        // res.write(message + "\n");
      });
      lsProcess.stderr.on("data", (data) => {
        console.log(`error: ${data}`);
      });
      lsProcess.on("exit", async (code) => {
        console.log(`Process ended with ${code}`);

        console.log("code", code, code <= 0, parseInt(code) <= 0);
        let rawdata = fs.readFileSync(jsonPath);

        let info = JSON.parse(rawdata);
        console.log("info", info);
        let results =
          code <= 0 ? extractInfo(info) : { msg: "Error while fetching ssl." };
        // const data = {
        //   scan_id: host.scan_id,
        //   host_id: host.host_id,
        //   results,
        // };

        console.log("results", results);

        // // The uniqueField is used to determine if the record exists
        // /////////await Certificates.upsertCertificate(data);

        resolve({ status: "success", key: host, data: info });
      });
    } catch (err) {
      reject({ status: "error", key: ip, error: err });
    }
  });
};

const extractInfo = (info) => {
  const keysToFind = [
    { key: "cert_serialNumber", name: "serial" },
    { key: "cert_commonName", name: "commonName" },
    { key: "cert_subjectAltName", name: "domains" },
    { key: "cert_expirationStatus", name: "daysLeft" },
    { key: "cert_expirationStatus", name: "isExpired" },
    { key: "cert_notBefore", name: "from" },
    { key: "cert_notAfter", name: "to" },
    { key: "cert_caIssuers", name: "issuer" },
  ];

  let certResult = info?.scanResult[0];
  let data = {};
  if (certResult) {
    let serverDefaults = certResult?.serverDefaults;

    ["ciphers", "protocols", "cipherTests"].map((key) => {
      let blockToFind = certResult[key];
      if (blockToFind && blockToFind.length > 0) {
        if (!data[key]) {
          data[key] = [];
        }
        blockToFind.map((item) => {
          if ("cipherTests" === key) {
            let ciph = item?.finding;
            if (ciph) {
              ciph = ciph.split(" ");
              if (ciph.length > 0) {
                ciph = ciph[ciph.length - 1].trim();
                data[key].push(ciph);
              }
            }
          } else {
            if (
              "offered" === item?.finding.trim() ||
              "offered with final" === item?.finding.trim()
            ) {
              data[key].push(item?.id);
            }
          }
        });
      }
    });

    if (serverDefaults && serverDefaults.length > 0) {
      serverDefaults.map((item) => {
        //   console.log("item", item);
        keysToFind.map((finder) => {
          if (finder.key === item.id) {
            data[finder.name] = item.finding;
          }
        });
      });
    }
  }
  return data;
};

(async () => {
  try {
    //
    // Manual testing...
    //
    //
    // let queue = {
    //   scanId: SCAN_ID,
    //   ipId: 3158,
    //   fileKey: "scan-110-3158.xml",
    // };
    // const fileContent = fs.readFileSync(queue.fileKey, "utf8");
    // await processPorts(fileContent, queue, {}, {}); //add to que....
    // // Manual testing...
    // return;

    let ips = IPS.split(",");

    if (ips && ips.length > 0) {
      console.log("ips processing");
      let jobs = [];

      for (var ip of ips) {
        await handleRequest(ip);
      }
      // ips.map((ip) => {
      //   if (ip) jobs.push(handleRequest(ip));
      // });

      // await Promise.all(
      //   jobs.map((p) =>
      //     p
      //       .then((res) => {
      //         res["status"] = "success";
      //         // info.push(res);
      //       })
      //       .catch((error) => {
      //         // If the domain isn't registered, if most certainly doesn't have SPF
      //         // records.
      //         console.log("error", error);
      //       })
      //   )
      // );
    } else {
      console.log("going single mode...");
      await handleRequest();
    }
  } catch (err) {
    console.error(err);
    // callback(Error(err));
  } finally {
    // console.log('ending db')
    // db.end();
    process.exit(0);
  }
})();
