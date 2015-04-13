■ 説明

ディレクトリごと、ファイル名ごとなどに接続数を制限するApacheモジュール。
制限に達した場合503を返す。


■ ディレクティブ

・DirLimit <num>
そのディレクティブが記述されたスコープの最大接続数を<num>に設定する。

・DirLimitScript <num>
そのディレクティブが記述されたスコープのスクリプトに対しての最大接続数を<num>に設定する。

・DirLimitPerSub <num>
サブディレクトリごとの接続数を<num>に設定する。<Directory>ディレクティブの内側でのみ使用可能。
（全てのサブディレクトリそれぞれにDirLimitを設定した場合と同等）

・DirLimitScriptPerSub <num>
サブディレクトリごとのスクリプトに対しての接続数を<num>に設定する。<Directory>ディレクティブの内側でのみ使用可能。
（全てのサブディレクトリそれぞれにDirLimitScriptを設定した場合と同等）

以上4ディレクティブはhttpd.confで使用可能。
.htaccessでは使用不可。（後述）

・DirLimitSetScriptType mime-type1 [mime-type2] ...
スクリプトとしてみなすMIMEタイプを設定する。

・DirLimitSetNoScriptType mime-type1 [mime-type2] ...
スクリプトとみなさないMIMEタイプを設定する。

以上2ディレクティブはhttpd.confや.htaccess（要AllowOverride Limit）で使用可能。

・DirLimitTableSize <size>
内部で用いるテーブルサイズを<size>に変更。（通常変更の必要なし）


■ ステータス

dirlimit-statusをハンドラに設定するとモジュールのステータスをリアルタイムに確認できる。


■ .htaccess対応について

現状(Apache2.2APIにおいて).htaccessごとにインスタンスを作って状態を持つ方法が見当たらず、制限系のディレクティブは.htaccessに対応できていません。具体的には、例えば/path/to/.htaccessの中でリミットを10に設定したとして、Apacheのディレクティブのmerge機構によってそのディレクトリのアクセスにおいてリミットが10であることはモジュールから知ることができますが、そのディレクティブに該当する一意なカウンタを持つことはできません。.htaccessの設定のmerge処理がリクエストの度に行われるのに対し、httpd.confのmerge処理はApacheの起動時に一度のみ行われるので、IDを付与するなどしてディレクティブごとに一意なカウンタを持つことができます。
また、.htaccessの絶対パスなどをキーにしてカウンタを持つことも考えられますが、モジュールのmerge関数でそのディレクティブの記述されている.htaccessのパスを取得する方法が無い（？）上、.htaccessの中で<File>ディレクティブなどを組み合わせた場合にも対応するためにはApacheのmerge機構に頼るしかありません。
これらを解決するスマートな方法があれば.htaccessに対応することはできると思われます。
