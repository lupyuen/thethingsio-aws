//  sigfox_parser is a thethings.io Cloud Function that is called when the
//  Sigfox Backend delivers a sensor device message to thethings.io (via HTTP callback).

//  In this example we assume that the Sigfox device is a UnaShield dev kit running
//  the following Arduino sketch "send-altitude.ino" that transmits 4 bytes of sensor data:
//  https://github.com/UnaBiz/unabiz-arduino/blob/master/examples/send-altitude/send-altitude.ino

//  Each 4-byte message transmitted by the device looks like "1c 30 36 1d"
//  When converted from hexadecimal to decimal, the message decodes to:
//  28 - temperature (degrees Celsius)
//  48 - humidity (0 to 100 percent)
//  54 - altitude (metres above sea level)
//  29 - temperature of the Sigfox transceiver module (degrees Celsius)
//  This function returns the sensor values as:
//  [ { key: 'tmp', value: 24 },
//    { key: 'hmd', value: 48 },
//    { key: 'alt', value: 54 },
//    { key: 'mod', value: 29 } ]
//  More details on the UnaShield: https://unabiz.github.io/unashield/

//  This function will have to be modified for different sensors.
//  It's also possible to parse simple types of payload data in the Sigfox Backend,
//  which will be passed to params as params.custom.FIELDNAME

function main(params, callback){
  //  Parse the 12-byte payload in the Sigfox message to get the sensor values.
  const sensorValues = [];
  if (!params) return callback(null, sensorValues);
  const custom = params.custom;
  const data = params.data;
  if (custom) {
    //  If custom sensor values are produced by the Sigfox Backend message parser,
    //  return the custom values. So params.custom.tmp becomes tmp.
    Object.keys(custom).forEach(key => {
      sensorValues.push({ key, value: custom[key] });
    });
  }
  if (data && data.length >= 2) {
    //  If payload data contains one or more bytes, return each byte as a sensor value
    //  data looks like "1c30361d".  We break into individual bytes (2 hex digits):
    //  tmp=0x1c, hmd=0x30, alt=0x36, mod=0x1d

  }

  const result = [
    //    {
    //Replace with your own payload parse
    //    "key": "temperature",
    //    "value": parseInt('0x'+params.data.substring(0,2))
    //    }
  ];
  callback(null, result)
}
