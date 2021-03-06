//  process_sensor_data is a thethings.io Trigger Function that is called
//  when a device message is received.  We call Cloud Function send_to_aws_kinesis
//  to send the sensor data to a AWS Kinesis Stream for realtime processing.
//  By calling a Cloud Function (max runtime of 2 seconds), we can take up to
//  20 seconds to send the data to AWS.

const unittest = typeof process !== 'undefined' && process && process.env && process.env.UNITTEST;  //  True for unit test.

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Main Function

function trigger(params, callback){
  if (params.action !== 'write') return callback(null);  //  Ignore reads, handle only writes.
  if (!params.values) return callback(null);  //  No new sensor values.

  //  We will call Cloud Function send_to_aws_kinesis to send the data.
  //  Prepare the params for the Cloud Function. Convert the sensor values array to an object.
  const cloudFunc = 'send_to_aws_kinesis';
  const cloudParams = {};
  const values = params.values;
  values.forEach(keyValue => {
    const key = keyValue.key;
    const value = keyValue.value;
    cloudParams[key] = value;
  });
  console.log(['*** process_sensor_data start', new Date().toISOString(), JSON.stringify({ cloudFunc, cloudParams }, null, 2)].join('-'.repeat(5)));

  //  Call the Cloud Function, passing the parameters.  In the next version we will call multiple functions.
  thethingsAPI.cloudFunction(cloudFunc, cloudParams, (error, result) => {
    if (error) return console.error('*** process_sensor_data error', error.message, error.stack, { cloudFunc, cloudParams });
    console.log(['*** process_sensor_data OK', new Date().toISOString(), JSON.stringify({ result, cloudFunc, cloudParams }, null, 2)].join('-'.repeat(5)));
  });

  //  Don't wait for cloud function to complete.
  return callback(null);
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Unit Test

//  Run Unit Test on local machine
if (unittest) {
  const params =
    { "action": "write", "values":
      [
        { "key": "tmp", "value": 28 },
        { "key": "hmd", "value": 48 },
        { "key": "alt", "value": 54 },
        { "key": "mod", "value": 29 }
      ]
    }
  ; setTimeout(() => trigger(params, (error) =>
    console.log({ error })), 1000);
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
