# Serverless_IOC_Gatherer
Purpose of this project was to gather all IOCs for Talos Intelligence's weekly threat roundup and post to MISP for storage.


# Requirements

- MISP Database
- API keys stored within SSM
  - MISP

- S3 Bucket containing zipped code.
  - deployment.zip


# Creating Deployment.zip

1. Unzip the dependencies.
2. Add all dependencies into a folder with all python files.
3. Zip the folder, name it deployment.zip
4. Place it into an S3 bucket.  



