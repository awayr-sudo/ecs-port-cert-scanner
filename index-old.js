const child_process = require("child_process");
const exec = child_process.exec;
// AWS
// Load the SDK for JavaScript
var AWS = require("aws-sdk");
const fs = require("fs");

const IAM_USER_KEY = process.env?.IAM_USER_KEY;
const IAM_USER_SECRET = process.env?.IAM_USER_SECRET;
const BUCKET_NAME = process.env?.BUCKET_NAME;
const RESULT_FILE_PREFIX = process.env?.RESULT_FILE_PREFIX;
const CMD = process.env?.CMD;
const SCAN_ID = process.env?.SCAN_ID;
const IPS = process.env?.IPS;
const QUEUE_URL = process.env?.QUEUE_URL;
const REGION = process.env?.REGION;

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
    console.log("Uploading file to s3....", logFile);
    let uploadInfo = await uploadFile(logFile, ipId, ip, resolve, reject);
    console.log("upload info", uploadInfo);
    console.log("Finished");
  });
};

const uploadFile = async (fileName, ipId, ip, resolve, reject) => {
  const fileContent = fs.readFileSync(fileName);
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
      console.log(`File uploaded successfully. ${data.Location}`);

      await addToQue(queue,resolve,reject); //add to que....
      resolve(`File uploaded successfully. ${data.Location}`);
    }
  });
};

const addToQue = async (data,resolve,reject) => {
  const sqs = new AWS.SQS({
    apiVersion: "2012-11-05",
    region: REGION,
  });

  var params = {
    // Remove DelaySeconds parameter and value for FIFO queues
    DelaySeconds: 10,
    MessageAttributes: {
      Title: {
        DataType: "String",
        StringValue: "Scan Processor",
      },
      Author: {
        DataType: "String",
        StringValue: "Cisotronix",
      },
    },
    MessageBody: JSON.stringify(data),
    // MessageDeduplicationId: "TheWhistler",  // Required for FIFO queues
    // MessageGroupId: "Group1",  // Required for FIFO queues
    QueueUrl: QUEUE_URL,
  };

  sqs.sendMessage(params, function (err, data) {
    if (err) {
      console.log("Queue->Error", err);
    } else {
      console.log("Queue->Success", data.MessageId);
    }
  });
};

(async () => {
  try {
    let ips = IPS.split(",");

    if (ips && ips.length > 0) {
      console.log("ips processing");
      let jobs = [];
      ips.map((ip) => {
        if (ip) jobs.push(handleRequest(ip));
      });

      await Promise.all(
        jobs.map((p) =>
          p
            .then((res) => {
              res["status"] = "success";
              // info.push(res);
            })
            .catch((error) => {
              // If the domain isn't registered, if most certainly doesn't have SPF
              // records.
              console.log("error", error);
            })
        )
      );
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
