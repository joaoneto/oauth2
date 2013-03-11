// original by: Steven Levithan <stevenlevithan.com> (http://blog.stevenlevithan.com)
// changes by: João Pinto Neto <joaopintoneto@gmail.com> (http://joaopintoneto.com)
// MIT License
function parseUri(str) {
  var key = ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
    m = /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/.exec(str),
    uri = {},
    i = 14;

  while (i--) uri[key[i]] = m[i] || "";

  uri['queryKey'] = {};
  uri[key[12]].replace(/(?:^|&)([^&=]*)=?([^&]*)/g, function ($0, $1, $2) {
    if ($1) uri['queryKey'][$1] = $2;
  });

  return uri;
}

module.exports.parseUri = parseUri;