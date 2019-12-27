# AWS Credential Tool - Profile Switcher

aws credetials switch tool for switching your default aws profile in `~/.aws/credentials` `~/.aws/config`.

## Usage

### Advance preparation
1. Set the AWS profile you want to switch.

    ```
    $ aws configure --profile "AWS Account Dev"
    $ aws configure --profile "AWS Account Stage"
    $ aws configure --profile "AWS Account Prod"
    ```
    
    Contents of `~/.aws/credentials`
    ```
    [default]
    aws_access_key_id = <AWS AccessKey Default>
    aws_secret_access_key = <AWS SecretAccessKey Default>
    [AWS Account Dev]
    aws_access_key_id = <AWS AccessKey Profile1>
    aws_secret_access_key = <AWS SecretAccessKey Profile1>
    [AWS Account Stage]
    aws_access_key_id = <AWS AccessKey Profile2>
    aws_secret_access_key = <AWS SecretAccessKey Profile2>
    [AWS Account Prod]
    aws_access_key_id = <AWS AccessKey Profile3>
    aws_secret_access_key = <AWS SecretAccessKey Profile3>
    ```

### actool Usage

1. choose profile

    ```
    $ actool
    
    # Use the arrow keys to navigate: ↑ ↓
    # Select Profile:
        default
      > AWS Account Dev
        AWS Account Stg
        AWS Account Prod
    ```

2. choose action

    * Set choose profile.

        Change the default profile of `~/.aws/credentials` to the selected profile.
        
    * Set choose sessionToken.
        
        Enter a temporary token for the MFA device.
        Using the selected profile, get a SessionToken in STS for AssumeRole and set it to the default profile of `~/.aws/credentials`　.

    ```
    # choose profile ["AWS Account Dev"]
    # Use the arrow keys to navigate: ↑ ↓
    # Select Action:
      > Set choose profile.
        Set choose sessionToken.
    ```

3. The default profile is changed.

    Contents of `~/.aws/credentials`
    ```
    [default]
    aws_access_key_id = <AWS AccessKey Profile1>
    aws_secret_access_key = <AWS SecretAccessKey Profile1>
    original_aws_access_key_id = <AWS AccessKey Default>
    original_aws_secret_access_key = <AWS SecretAccessKey Default>
    [AWS Account Dev]
    aws_access_key_id = <AWS AccessKey Profile1>
    aws_secret_access_key = <AWS SecretAccessKey Profile1>
    [AWS Account Stage]
    aws_access_key_id = <AWS AccessKey Profile2>
    aws_secret_access_key = <AWS SecretAccessKey Profile2>
    [AWS Account Prod]
    aws_access_key_id = <AWS AccessKey Profile3>
    aws_secret_access_key = <AWS SecretAccessKey Profile3>
    ```
 