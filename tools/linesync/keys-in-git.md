
=== Some musings about a way to store lets-encrypt-generated ircd pem keys in git without flooding out the history ===


Save the certificate
  git tag -f servername-cert $(command to generate cert | git hash-object -w --stdin)

Read the certificate
  git show servername-cert


note about abusing remote tags:
https://stackoverflow.com/questions/19298600/tag-already-exists-in-the-remote-error-after-recreating-the-git-tag

Delete the tag on the server
  git push origin :refs/tags/servername-cert

pushing and pulling include the tags
  git pull --tags
  git push --tags


So the sequence would be:
  * Get new certificate from LE
  * Put new certificate in git tag using the hash-object thing with -f to overwrite the old
  * Delete the old tag on the server with the :refs/tags/ thing
  * git push --tags to send the new tag(s) to the server


Then in gitsync.sh we need to do git pull --tags to get the latest (or just our needed tag?) 
and save it to the ircd.pem file (key file will need to be seperated) and HUP the ircd if it changed.


