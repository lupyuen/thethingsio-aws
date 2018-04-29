//  transformSensorJSON is a Lambda Function for Amazon Kinesis Firehose stream
//  processing. It appends a newline to each JSON record. This allows the
//  Athena crawler to index the sensor JSON files in S3 correctly.

//  Settings for the transformSensorJSON Lambda Function:
//  Runtime: Node.js 8.10
//  Handler: index.handler
//  Execution Role: lambda_basic_execution
//  Memory: 128 MB
//  Timeout: 1 min

console.log('Loading function');

exports.handler = (event, context, callback) => {
  let success = 0; // Number of valid entries found
  let failure = 0; // Number of invalid entries found

  //  Process the list of records and transform them
  const output = event.records.map((record) => {
    // Kinesis data is base64 encoded so decode here
    console.log(record.recordId);
    let payload = new Buffer(record.data, 'base64').toString();
    console.log('>>> Decoded payload:', payload);

    // Append a newline to the record.
    payload += '\n';
    console.log('<<< Transformed payload:', payload);

    //  Return the transformed record.
    success++;
    return {
      recordId: record.recordId,
      result: 'Ok',
      data: new Buffer(payload).toString('base64'),
    };

  });
  console.log(`Processing completed.  Successful records ${success}, Failed records ${failure}.`);
  callback(null, { records: output });
};

