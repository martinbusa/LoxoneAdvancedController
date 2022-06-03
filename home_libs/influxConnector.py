from influxdb import InfluxDBClient
from datetime import datetime,timezone
import logging
logger = logging.getLogger(__name__)


class Connector():
    def __init__(self, serverIp, serverPort, dbName, measurementName):
        #Connect to influx db
        self.measurementName = measurementName
        self.client = InfluxDBClient(host=serverIp, port=serverPort)
        self.client.switch_database(dbName)

    def submitData(self, values):
        #Submit data to influxDB
        date = datetime.now(timezone.utc)
        json_body = [
            { "measurement":self.measurementName,
              "time":date.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "fields":{}
                }
            ]
        for value in values:
            json_body[0]["fields"][value] = float(values[value])
        logger.debug("Write data to influx")
        self.client.write_points(json_body)
