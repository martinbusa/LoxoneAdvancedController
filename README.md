# LoxoneAdvancedController
Python application allowing to setup an advanced controller on local server. The application is intended to run advanced control computations too complex to be run directly on Loxone.

Based on demo implementation from alxgross (https://github.com/alxgross/Loxone_Websockets_Demo) and my fork that fixes some problems.
Developed with Thonny (running python 3.7.9) - a simple but helpful python IDE (https://thonny.org/)

### Warning
I'm a C++ developer (not a Python developer, and have very little experience with webapplications, sockets, etc.), this project is purely as a hobby implemented for my own needs. I am sure that it contains a lot of inefficient code and doesn't cope with all the error states. I would be happy to accept any contributions improving these things.

# Summary
The application has two main functionalities:
* Logging data and saving it to InfluxDB running on local server
    * Status data from Loxone
    * Weather data from OpenWeatherMap
* Controlling Loxone
    * Control based on the data logged from Loxone and provided control model

### Example use-case
I intend to use the application to controll AC and automatic curtains connected to Loxone. I am not happy with possibilities of the current Room Controller block in Loxone. Since the controll of curtains in conjuction with AC depends also on outside weather, sun angle etc., I started with collecting all the data in InfluxDB. Then I plan to train AI model on this data which will be performing the actual control.
