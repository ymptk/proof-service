# Setup

1. Download zk files (guardianhash.wasm,guardianhash.r1cs,guardianhash_0001.zkey),
put them in a folder. Then config these paths in the appsettings.json.
    ```
    "ProverSetting": {
        "WasmPath": "/fakepath/guardianhash.wasm",
        "R1csPath": "/fakepath/guardianhash.r1cs", 
        "ZkeyPath": "/fakepath/guardianhash_0001.zkey"
      },
    ```


2. Clone this repo ``https://github.com/stevenportkey/test-aelf-node`` to your local.
And copy the keystore file to keys folder of aelf, for example: ``/fakepath/.local/share/aelf/keys``.