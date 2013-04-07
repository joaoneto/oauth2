module.exports = function (oauth2) {
  var Client = oauth2.Client;

  var _listClients = function (req, res) {
    var secret = oauth2.genClientSecret();

    Client.find({}).sort({'_id': -1}).execFind(function (err, docs) {
      if (err)
        return null;

      var result = ['<html><body>'];
      result.push('<form action="", method="post">Client secret: <input name="secret" readonly="readyonly" value="');
      result.push(secret);
      result.push('"> Redirect uri: <input name="redirect_uri"><input type="submit"></form>');
      result.push('<h2>List</h2><table><tr><td>client_id</td><td>client_secret</td><td>request_uri</td></tr>');

      for (var x = 0, len = docs.length; x < len; x++)
        result.push(['<tr><td>', docs[x]._id, '</td><td>', docs[x].secret, '</td><td>', docs[x].redirect_uri, '</td></tr>'].join(''));

      result.push('</table>');
      result.push('</body></html>')

      res.send(result.join(''));
    });
  };

  var _createClient = function (req, res) {
    if (!req.body || !req.body.redirect_uri || !req.body.secret)
      res.send('Client secret or redirect uri invalid, or not present, please try again!').end();

    var new_client = new Client(req.body);
    new_client.save(function (err, client) {

      if (err)
        return req.send('Error saving new client, please try again!').end();

      var result = ['<h2>New client created!</h2><a href="/clients">« back to list</a>'];

      result.push('<table><tr><td>client_id</td><td>client_secret</td><td>redirect_uri</td></tr>');
      result.push('<tr><td>');
      result.push(client._id);
      result.push('</td><td>');
      result.push(client.secret);
      result.push('</td><td>');
      result.push(client.redirect_uri);
      result.push('</td></tr></table>');

      res.send(result.join('')).end();
    });
  };

  var _authorization = function (req, res) {

  };

  return {
    listClients: _listClients,
    createClient: _createClient,
    authorization: _authorization
  };
}