import requests
import time
import logging
logger = logging.getLogger(__name__)

class WeatherService:
    def __init__(self, lat, lon, apiKey, dataRefreshTime):
        self.lat = lat
        self.lon = lon
        self.apiKey = apiKey
        self.dataRefreshTime = dataRefreshTime
        self.weatherId=0
        self.weatherString="Unknown"
        self.temp=0
        self.tempFeel=0
        self.pressure=0
        self.humidity=0
        self.windSpeed=0
        self.windDir=0
        self.clouds = 0
        self.rain1h=0
        self.snow1h=0
        self.dataTimeLin=0
        #fetch initial data
        self.fetchData()
        
    def getData(self):
        if time.time() - self.fetchTime >= self.dataRefreshTime:
            #its time to fetch new data
            self.fetchData()
        return { "weatherId": self.weatherId,
                 "temp": self.temp, "tempFeel": self.tempFeel, "press": self.pressure,
                 "humid": self.humidity, "ws": self.windSpeed, "wd": self.windDir,
                 "clouds": self.clouds, "rain": self.rain1h, "snow": self.snow1h,
                 "dt": self.dataTimeLin }

        
    def fetchData(self):
        self.fetchTime = time.time()
        response = requests.get(
            "https://api.openweathermap.org/data/2.5/weather?lat={}&lon={}&appid={}&units=metric"
            .format(self.lat,self.lon,self.apiKey))
        if response.status_code != 200:
            logger.error("Error while reading weather data, response status: {}".format(response.status_code))
        responseJson = response.json()
        if not responseJson:
            logger.error("Error while reading weather data, no JSON in response")
            return { "status": -1}
        #basic weather info
        if 'weather' in responseJson:  
            self.weatherId=responseJson['weather'][len(responseJson['weather'])-1]['id'] 
            self.weatherString=responseJson['weather'][len(responseJson['weather'])-1]['main']
        #atmospherical info
        if 'main' in responseJson:    
            self.temp=responseJson['main']['temp']
            self.tempFeel=responseJson['main']['feels_like']
            self.pressure=responseJson['main']['pressure']
            self.humidity=responseJson['main']['humidity']
        #wind info
        if 'wind' in responseJson:
            self.windSpeed=responseJson['wind']['speed']
            self.windDir=responseJson['wind']['deg']
        #clouds info
        if 'clouds' in responseJson:
            self.clouds=responseJson['clouds']['all']
        #rain
        if 'rain' in responseJson:
            self.rain1h=responseJson['rain']['1h']
        #snow
        if 'snow' in responseJson:
            self.snow1h=responseJson['snow']['1h']
        if 'dt' in responseJson:
            self.dataTimeLin=responseJson['dt']
        logger.debug("WeatherService: Fetched new data")
            
