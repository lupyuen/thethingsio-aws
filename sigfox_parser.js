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
//  [ { key: 'tmp', value: 28 },
//    { key: 'hmd', value: 48 },
//    { key: 'alt', value: 54 },
//    { key: 'mod', value: 29 } ]
//  More details on the UnaShield: https://unabiz.github.io/unashield/

//  This function will have to be modified for different sensors.
//  It's also possible to parse simple types of payload data in the Sigfox Backend,
//  which will be passed to params as params.custom.FIELDNAME

const unittest = typeof process !== 'undefined' && process && process.env && process.env.UNITTEST;  //  True for unit test.

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Main Function

function main(params, callback){
  //  Parse the 12-byte payload in the Sigfox message to get the sensor values.
  //  Upon completion, callback will be passed an array of { key, value } sensor values.
  if (!params) return callback(null, []);  //  Nothing to parse, quit.
  const sensorValues = {};
  const custom = params.custom;
  const data = params.data;
  if (custom) {
    //  If custom sensor values are produced by the Sigfox Backend message parser,
    //  return the custom values. So params.custom.tmp becomes tmp.
    Object.assign(sensorValues, custom);
  }
  if (data && data.length >= 2 && data.length <= 8) {  //  Ignore Structured Messages.
    //  If payload data contains one or more bytes, return each byte as a sensor value
    //  data looks like "1c30361d".  We break into individual bytes (2 hex digits):
    //  tmp=0x1c, hmd=0x30, alt=0x36, mod=0x1d.  Convert from hexadecimal to decimal.
    if (data.length >= 2) sensorValues.tmp = parseInt(data.substr(0, 2), 16);
    if (data.length >= 4) sensorValues.hmd = parseInt(data.substr(2, 2), 16);
    if (data.length >= 6) sensorValues.alt = parseInt(data.substr(4, 2), 16);
    if (data.length >= 8) sensorValues.mod = parseInt(data.substr(6, 2), 16);
  }

  // Unit Test: Check whether the decoded sensor values match the expected sensor values.
  if (unittest && params.expectedSensorValues) {
    const expected = params.expectedSensorValues;
    if (JSON.stringify(expected) === JSON.stringify(sensorValues))
      console.log('*** Unit Test: Expected sensor values OK');
    else throw new Error([
      'Expected sensor values:',
      expected,
      'Got:',
      sensorValues,
    ].join('\n'));
  }

  //  Convert sensor values from object into an array of { key, values }.
  const sensorValuesArray = [];
  Object.keys(sensorValues).forEach(key => {
    sensorValuesArray.push({ key, value: sensorValues[key] });
  });
  //  Return the sensor value array to thethings.io, which will trigger the
  //  process_sensor_data Trigger Function.
  callback(null, sensorValuesArray)
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Unit Test

//  Run Unit Test on local machine
if (unittest) {
  const params =
    {"data": "1c30361d",
      "expectedSensorValues": {
        "tmp": 28,
        "hmd": 48,
        "alt": 54,
        "mod": 29
      }
    }
  ; setTimeout(() => main(params, (error, result) =>
    console.log({ error, result })), 1000);
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
