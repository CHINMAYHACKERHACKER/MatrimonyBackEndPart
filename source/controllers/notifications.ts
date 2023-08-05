//#region Notification Code

const notification_options = {
    priority: "high",
    timeToLive: 60 * 60 * 24
};
var admin = require("firebase-admin");
var serviceAccount = require("../../matrimony-firebase-adminsdk.json");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const sendMultipleNotification = async (fcmTokens: any, id: any, title: any, message: any, json: any, dateTime: any, ImageUrl: any, type: any) => {
    var result = null;
    try {
        var dataBody = {
            id: id,
            title: title,
            message: message,
            type: type,
            json: json,
            dateTime: dateTime
        }

        const messaging = admin.messaging();

        var payload = {
            notification: ImageUrl ? {
                title: title,
                body: message,
                imageUrl: ImageUrl,
            } : {
                title: title,
                body: message
            },
            data: {
                click_action: "FLUTTER_NOTIFICATION_CLICK",
                body: JSON.stringify(dataBody),

            },
            android: {
                priority: 'high',
            },
            tokens: fcmTokens,
        };

        result = await messaging.sendMulticast(payload);

        console.log(result)
    }
    catch (e) {
        console.log(e);
        result = e;
    }
    return result;
};

export default { sendMultipleNotification }