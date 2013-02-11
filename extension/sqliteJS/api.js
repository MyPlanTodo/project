
var {Cc, Ci, Cu} = require("chrome");

var {FileUtils} = Cu.import("resource://gre/modules/FileUtils.jsm");
var {Services} = Cu.import("resource://gre/modules/Services.jsm");

function DataProcess(user) {
    this.fileDB = FileUtils.File("~/foo.db");
    this.conn = Services.storage.openDatabase(this.fileDB);
}

DataProcess.prototype.close = function() {
    this.conn.close();
}

/*        ADDING METHODS          */

DataProcess.prototype.addFriends = function(friends) {
    if (!friends) {
        throw "friends has to be an array list of tuples";
    }
    tmp = friends.shift();
    query = "INSERT INTO Friends ('pseudo', 'pubKey') VALUES ('" + tmp[0] + "', '" + tmp[1] + "')"
        for (f in friends) {
            query += ", ('" + friends[f][0] + "', '" + friends[f][1] + "')";
        }
    query += ";";
    this.conn.executeSimpleSQL(query);
}

DataProcess.prototype.addList = function(listname) {
    if (!listname) {
        throw "listname has to be a non empty string";
    }
    this.conn.executeSimpleSQL("INSERT INTO Lists ('list_name') VALUES ('" + listname + "');");
}

DataProcess.prototype.addLink = function(friend, listname) {
    if (!friend || !listname) {
        throw "friend and listname have to be two strings";
    }
    this.conn.executeSimpleSQL("INSERT INTO FriendsLists SELECT id_friend, id_list from Friends, Lists where pseudo = '" + friend + "' and list_name = '" + listname + "';");
}

/*        UPDATE METHODS          */

DataProcess.prototype.updatePubKey = function(friend, newPubKey) {
    if (!friend || !newPubKey) {
        throw "friend and newPubKey have to be two strings";
    }
    this.conn.executeSimpleSQL("UPDATE Friends SET pubKey = '" + newPubKey + "' where pseudo = '" + friend + "';");
}


/*        REMOVING METHODS          */

DataProcess.prototype.removeFriend = function(friend) {
    if (!friend) {
        throw "friend has to be a non empty string"
    }
    this.conn.executeSimpleSQL("DELETE FROM Friends WHERE pseudo = '" + friend + "';");
}

DataProcess.prototype.removeList = function(listname) {
    if (!listname) {
        throw "listname has to be a non empty string"
    }
    this.conn.executeSimpleSQL("DELETE FROM Lists WHERE list_name = '" + listname + "';");
}

DataProcess.prototype.removeLink = function(friend, listname) {
    if (!friend || !listname) {
        throw "friend and listname have to be two strings";
    }
    this.conn.executeSimpleSQL("DELETE FROM FriendsLists WHERE id_friend = (SELECT id_friend FROM Friends WHERE pseudo = '" + friend + "') and id_list = (SELECT id_list FROM Lists WHERE list_name = '" + listname + "');"); 
}

/*        GETTERS           */

DataProcess.prototype.getUsers = function() {
    var result = [];
    var statement = this.conn.createStatement("SELECT pseudo FROM Friends");
    while (statement.executeStep()) {
        result.push(statement.getString(0));
    }
    return result;
}

DataProcess.prototype.getUsersFromList = function(listname) {
    if (!listname) {
        throw "listname has to be a non empty string";
    }
    var result = [];
    var statement = this.conn.createStatement("SELECT pseudo FROM (FriendsLists fl INNER JOIN Friends f ON (fl.id_friend = f.id_friend)) t INNER JOIN Lists l ON (t.id_list = l.id_list) WHERE list_name = '" + listname + "';");
    while (statement.executeStep()) {
        result.push(statement.getString(0));
    }
    return result;
}

DataProcess.prototype.getLists = function() { 
    var result = [];
    var statement = this.conn.createStatement("SELECT list_name FROM Lists");
    while (statement.executeStep()) {
        result.push(statement.getString(0));
    }
    return result;
}

DataProcess.prototype.getPubKey = function(friend) {
    if (!friend) {
        throw "friend has to be a non empty string";
    }
    var statement = this.conn.createStatement("SELECT pubKey FROM Friends where pseudo = '" + friend + "';");
    statement.executeStep();
    return statement.getString(0);
}

DataProcess.prototype.hasLink = function(friend, listname) {
    if (!friend || !listname) {
        throw "friend and listname have to be two strings";
    }

    var statement = this.conn.createStatement("SELECT 1 FROM (FriendsLists INNER JOIN Friends ON " +
            "(FriendsLists.id_friend = Friends.id_friend)) t INNER JOIN Lists ON " +
            "(t.id_list = Lists.id_list) WHERE pseudo = '" + friend + "' AND list_name = '" + listname + "';");
    if (statement.executeStep()) {
        return statement.getString(0) == 1;
    }
    return false;
}
