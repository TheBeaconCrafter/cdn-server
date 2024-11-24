#!/bin/bash

# Create a new screen session named "cdn"
screen -dmS cdn

# Run the server inside the screen session
screen -S cdn -X stuff "node index.js\n" 

echo "Server started in screen session 'cdn'"