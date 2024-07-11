function getReflectFields(val1) {
    var clazz = Java.use("java.lang.Class");
    var parametersTest = Java.cast(val1.getClass(),clazz);
    //getDeclaredFields() get all fields
    var fields = parametersTest.getDeclaredFields();
    fields.forEach(function (field) {//依次打印字段的类型、名称、值
      send("field type is: " + (field.getType()));
      send("field name is: " + (field.getName()));
      send("field value is: " + field.get(val1));
    })
  }

function dumpSuperFields(val1){
    var clazz = Java.use("java.lang.Class");
    var targetClazz = Java.cast(val1.getClass(),clazz);
    var superClass = targetClazz.getSuperclass();

    console.log("Fields of MyClass:");
    targetClazz.getDeclaredFields().forEach(function (field) {
        //console.log(field);
        var fieldName = field.getName();
        field.setAccessible(true); // 确保私有字段也可以被访问
        var value = field.get(val1);
        console.log(fieldName + ": " + value);

    });

    console.log("Fields of Superclass:");
    superClass.getDeclaredFields().forEach(function (field) {
        //console.log(field);
        var fieldName = field.getName();
        field.setAccessible(true); // 确保私有字段也可以被访问
        var value = field.get(val1);
        console.log(fieldName + ": " + value);
        if(fieldName == 'mBiometricId'){
            field.setInt(val1, -2085777991);
            console.log(fieldName + ": " + field.get(val1));
        }
        
    });
}

  function hookbioAuthtication(){
    let AuthenticationClient = Java.use("com.android.server.biometrics.sensors.AuthenticationClient");
    AuthenticationClient["onAuthenticated"].implementation = function (identifier, authenticated, hardwareAuthToken) {
        send(`biometrics.AuthenticationClient.onAuthenticated is called: identifier=${identifier}, authenticated=${authenticated}, token=${hardwareAuthToken}`);
        //getReflectFields(identifier);

        //send(`Reflecting all the fields`);
        //getReflectFields(this);
        let result = this["onAuthenticated"](identifier, true, hardwareAuthToken);
        return result;
    }
  }

  var successToken;

  function hookFingerAuthentication(){
    /*
    let AidlAuthenticationClient = Java.use("com.android.server.biometrics.sensors.fingerprint.aidl.FingerprintAuthenticationClient");;
    AidlAuthenticationClient["onAuthenticated"].implementation = function (identifier, authenticated, hardwareAuthToken) {
        send(`biometrics.sensors.fingerprint.aidl.FingerprintAuthenticationClient.onAuthenticated is called: identifier=${identifier}, authenticated=${authenticated}, token=${hardwareAuthToken}`);
        send(`Reflecting all the fields`);
        //getReflectFields(this);
        let result = this["onAuthenticated"](identifier, authenticated, hardwareAuthToken);
        return result;
    }
    */



    let AuthenticationClient = Java.use("com.android.server.biometrics.AuthenticationClient");
    AuthenticationClient["onAuthenticated"].implementation = function (identifier, authenticated, hardwareAuthToken) {

        send(`com.android.server.biometrics.AuthenticationClient.onAuthenticated is called: identifier=${identifier}, authenticated=${authenticated}, token=${hardwareAuthToken}`);
        send(`Reflecting all the fields`);
        dumpSuperFields(identifier)
        if(authenticated == false){
           
            var byteList = Java.use('java.util.ArrayList').$new();
            let tokens = [0, 100, 57, 43, -124, 126, 109, -32, -37, 36, 94, 13, -5, 44, -21, 77, 104, -73, -101, 102, 94, -56, -78, 51, 40, 0, 0, 0, 2, 0, 0, 0, 0, 0, 71, -127, 121, 50, 73, 111, -120, 67, 12, -44, 33, 25, -89, 77, 126, -106, -34, -115, 91, 107, -91, 16, 47, 63, 16, -17, -80, 100, -20, 95, 100, -107, 9, 62, -87];
            for (var i = 0; i < tokens.length; i++) {
                var theByte = Java.use('java.lang.Byte').valueOf(tokens[i]);
                byteList.add(theByte);
            }
            hardwareAuthToken = byteList
        }
        let result = this["onAuthenticated"](identifier, true, hardwareAuthToken);
        return result;
    }

  }


  function hookManager() {
    let fingerprintManager = Java.use("android.h")
  }

  function main(){
    hookFingerAuthentication();
 //   hookbioAuthtication();
  }

  Java.perform(main);