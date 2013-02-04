var {Cc, Ci, Cu} = require("chrome");

var {FileUtils} = Cu.import("resource://gre/modules/FileUtils.jsm");
var {Services} = Cu.import("resource://gre/modules/Services.jsm");

/* Example of writing in a file */
var f = FileUtils.File("~/foo");
var data = "foo";
var stream = FileUtils.openFileOutputStream(f);
stream.write(data, data.length);

stream.close()

/* Example of insert and select in a sqlite database */
var fileDB = FileUtils.File("~/test.db");
var dbConn = Services.storage.openDatabase(fileDB);

// dbConn.executeSimpleSQL("insert into users (user_name, passwd) values ('zako', 'kodoque');");

var statement = dbConn.createStatement("SELECT id, user_name FROM users");

    /*
     * rc = statement.executeStep();
     * console.log(statement.columnCount);
     * console.log(statement.getColumnName(1));
     * console.log(statement.getString(1));
     *
     * rc = statement.executeStep();
     * console.log(statement.columnCount);
     * console.log(statement.getColumnName(1));
     * console.log(statement.getString(1));
     * */

while (statement.executeStep()) {
    let value = statement.getString(1);
    console.log(value);
}

dbConn.close();
