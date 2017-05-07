# Cyber Threat Intelligence APIs
a collection of python programs utilizing threat intelligence APIs to query different cyber threat intelligence resources, parse the data and return it in a useful form for analysts.

## Currently Supported Feeds:
- shodan
- virus total

## General Usage
- API key read from a separate file defined with the '-k' option, required.
- Information to be quiered (right now mostly IP addresses) must be written one entry per line in a .txt file; defined with '-i', required.
- Output file is formatted to a .csv file and is defined with '-o', optional. Results may vary on how organized the file is based on how consistent output is from the API.
