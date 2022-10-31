Tripcode
===

Just another tripcode library.

Usage
-------

```php
<?php

use Tripcode\Tripcode;

$foo = new Tripcode("FOO#BAR#BAZ", "SECRET");
var_dump($foo->getName());
var_dump($foo->getKey());
var_dump($foo->getTripcode());
```

```
string(3) "FOO"
string(8) "#BAR#BAZ"
string(33) "!PKx7yyhmuk!!dHJpcFNFQ1JFVFwmDQ=="
```

License
-------

MIT License
