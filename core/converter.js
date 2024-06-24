const xml2js = require("xml2js");
/**
 *
 * @param {*} xmlInput
 * @param {*} onFailure
 * @returns {host[]} - Array of hosts
 */
function convertRawJsonToScanResults(xmlInput) {
  let tempHostList = [];

  if (!xmlInput.nmaprun.host) {
    //onFailure("There was a problem with the supplied NMAP XML");
    return tempHostList;
  }

  xmlInput = xmlInput.nmaprun.host;

  tempHostList = xmlInput.map((host) => {
    const newHost = {
      hostname: null,
      ip: null,
      mac: null,
      openPorts: null,
      osNmap: null,
    };

    //Get hostname
    if (
      host.hostnames &&
      host.hostnames[0] !== "\r\n" &&
      host.hostnames[0] !== "\n"
    ) {
      newHost.hostname = host.hostnames[0].hostname[0].$.name;
    }

    //get addresses
    host.address.forEach((address) => {
      const addressType = address.$.addrtype;
      const addressAdress = address.$.addr;
      const addressVendor = address.$.vendor;

      if (addressType === "ipv4") {
        newHost.ip = addressAdress;
      } else if (addressType === "mac") {
        newHost.mac = addressAdress;
        newHost.vendor = addressVendor;
      }
    });

    //get ports
    if (host.ports && host.ports[0].port) {
      const portList = host.ports[0].port;

      const openPorts = portList.filter((port) => {
        return port.state[0].$.state === "open";
      });

      newHost.openPorts = openPorts.map((portItem) => {
        // console.log('port item', portItem)
        // console.log('ports:',JSON.stringify(portItem, null, 4))

        const port = parseInt(portItem.$.portid);
        const protocol = portItem.$.protocol;
        const serviceObj = portItem?.service && Array.isArray(portItem.service) ?  portItem.service[0] : null
        const service = serviceObj?.$.name || null;
        const tunnel = serviceObj?.$.tunnel|| null;
        const method = serviceObj?.$.method|| null;
        const product = serviceObj?.$.product|| null;
        const version = serviceObj?.$.version|| null;
        const extrainfo = serviceObj?.$.extrainfo|| null;
        const cpe = serviceObj?.cpe;
        

        let portObject = {};
        if (port) portObject.port = port;
        if (protocol) portObject.protocol = protocol;
        if (service) portObject.service = service;
        if (tunnel) portObject.tunnel = tunnel;
        if (method) portObject.method = method;
        if (product) portObject.product = product;
        if (version) portObject.version = version;
        if (extrainfo) portObject.extrainfo = extrainfo;
        if (cpe) portObject.cpe = cpe;
        return portObject;
      });
    }

    if (host.os && host.os[0].osmatch && host.os[0].osmatch[0].$.name) {
      newHost.osNmap = host.os[0].osmatch[0].$.name;
    }
    return newHost;
  });

  return tempHostList;
}

function convertToJson(data) {
  let results;
  //turn NMAP's xml output into a json object
  xml2js.parseString(data, (err, result) => {
    if (err) {
      console.log("error", "Error converting XML to JSON in xml2js: " + err);
    } else {
      results = convertRawJsonToScanResults(result, (err) => {
        console.log(
          "error",
          "Error converting raw json to cleans can results: " +
            err +
            ": " +
            result
        );
      });
      // this.scanComplete(results);

      // console.log(results[0], results.length);
    }
  });
  return results[0];
}

module.exports = { convertToJson };
