---
title: "XSSの対策と影響"
description: "脆弱性診断の指摘事項に対するベストプラクティスが実施できない場合の緩和策ガイド"
weight: 8
bookToc: true
draft: false
---

# XSSの対策と影響
クロスサイトスクリプティング（XSS）とは、Webアプリケーションがユーザー入力を適切に処理せず、そのままHTMLやJavaScriptとして実行してしまう脆弱性である。
OWASP においても代表的なWeb脆弱性として位置づけられています。

## 脆弱性概要/影響
XSSは、信頼できないスクリプトがブラウザ側で実行されてしまう脆弱性です。

主な分類:
* 格納型 (Stored): サーバーに悪意あるスクリプトが保存され、閲覧した全ユーザーに影響が及ぶもの
* 反射型 (Reflected): URLパラメータ等に含まれたスクリプトが、そのままレスポンスとして返ることで発火するもの
* DOM-based: JavaScriptによるクライアント側の処理不備で発生するもの

発生頻度の高いケース:
* リッチテキストエディタや掲示板など、文字装飾のためにHTMLタグを許可したい場合
* 「お知らせ」機能などで一部の装飾を許可している箇所
* AIエージェントによる出力: 生成AIがMarkdownやJSON形式で出力した内容を、そのままブラウザでレンダリングする際の不備

### 主な影響:
* セッション情報の搾取: Cookie（HttpOnly属性がない場合）の読み取りによるなりすまし 。
* 画面の改ざん・破壊: 意図しないコンテンツの表示やUIの崩壊 。
* 情報の漏洩: 攻撃者のドメインへ機密情報を送信されるリスク 。

## 根本対策
XSS対策の原則は信頼できない入力をそのまま実行させないことです。
そのため、コンテキストに応じた出力エンコードが対策となります。
HTML要素、属性、JavaScript内など、データの挿入場所に応じた適切なエスケープ（< → &lt; など）を徹底してください。

安全な関数を用いてDOMを構築することも対策の一つです。
例えばinnerHTMLではなくinnerTextを用いて組み立てれば、エスケープを行わずともHTMLとして解釈される恐れが無いため発火しません。

## その他の対策
エスケープが行えない場合の対策です。
根本的な対策と緩和策との区別が不明瞭であるため、その他の対策として紹介します。


### DOMPurify の利用:
DOMPurifyはJavaScript製のライブラリで、特定のタグ（<b>, <h1>, <i>等）のみを許可（ホワイトリスト形式）するサニタイズライブラリです。
ユーザ入力を安全なHTMLに変換してからDOMに挿入することで、XSSの発生を防ぎます。
自前でパースを行うのは現実的ではないため、このようなライブラリがよく用いられます。

```
const clean = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: ["b", "i", "a"],
  ALLOWED_ATTR: ["href"]
});
element.innerHTML = clean;
```

内部的にはDOMを解析して危険なノードや属性を削除するため、単純な正規表現ベースのフィルタよりも堅牢です。
また、SVGやMathMLといった複雑なケースにも対応しています。
一方で、設定ミス（過剰な許可）により脆弱性を招く可能性があるため、最小権限の原則で許可リストを設計する必要があります。

また、ブラウザネイティブなライブラリではないため、非常に稀ですが、ブラウザ独自の仕様に対応しきれずバイパスされてしまうこともあります。
ただし、この場合は脆弱性として認知され速やかに修正されるため、やはり自前でパース処理を書くよりも安全であると考えられます。


### setHTML API (Sanitizer API):
Sanitizer API はブラウザ標準で提供されるHTMLサニタイズ機構で、ユーザ入力などの不正なHTMLを安全な形に変換してDOMに挿入できます。従来の innerHTML はスクリプトやイベント属性（onerror など）をそのまま解釈してしまうため危険ですが、setHTML() を使うことで許可された要素・属性のみが反映されます。例えば以下のように利用します。
```
// setHTMLを実行
document.body.setHTML("<script>alert(1);</script><s onclick=alert(1)>TEXT</s><a href='javascript:alert(1)'>alert</a><a href='/top.html'>TOP</a><img src=1 />")

//<s>TEXT</s><a>alert</a><a href="/top.html">TOP</a> が返される
document.body.innerHTML;
```

このように ```<script>``` や ```onclick```、さらには```javascript:```プロトコルまで自動で除去してくれます。
便利な関数ですが、現状では一部のブラウザで実験的な機能（提案段階）です。



### Trusted Types API:
CSPとポリシーオブジェクトを用いてinnerHTML等への危険な代入を禁止するとともに、一定の変換処理を行った値のみしか代入できないようにする技術です。

```
//CSPで require-trusted-types-for 'script'しておく

//動く
const policy = trustedTypes.createPolicy("default", {
  createHTML: (input) => DOMPurify.sanitize(input)
});
document.body.innerHTML = policy.createHTML("<s>Text</s>");

//動かない
document.body.innerHTML = "<s>Text</s>";
```

このように、DOMPurifyをかけた文字列しか代入できないよう縛ることができます。



### Iframe Sandbox / 別オリジンの活用:
仮にスクリプトが実行されても影響を限定するという隔離戦略です。
代表例がiframe sandboxです。

```
//sandbox属性によって隔離
<iframe src="/user/file/1" sandbox=""></iframe>

// usercontentドメインを利用した隔離
<iframe src="https://usercontent.example.com/user/file/1"></iframe>
```

sandbox 属性によりスクリプト実行やポップアップの表示、トップレベル遷移などを制限できます。
また別オリジンで配信することで、CookieやLocalStorageへのアクセスも分離できます。

ただし、別オリジンに隔離するだけの場合、domain属性のついたCookieのようにSameOriginPolicyに縛られない情報へはアクセスできてしまう点に注意が必要です。
sandbox属性は指定した属性値を許可する＝何も指定しない状態が最もセキュアであり、許可するほど脆弱になる　という属性のため、利用する際は空の属性値を用いるべきです。
特に、```allow-same-origin```や```allow-scripts```を用いる場合は、何も指定しないよりもセキュリティレベルが落ちる可能性があります。

また、あくまでiframeに適用される制限であって、ユーザが能動的に別タブで開くなど、iframe外で動作させてしまうと、普通にスクリプトが動作してしまう点にも注意が必要です。


### Content Security Policy (CSP):
スクリプトの取得元やインラインスクリプトの実行を制限する強力な対策です。
外部サイトからのスクリプト読み込みや eval の実行を制限したり、scriptタグ中のnonce値がレスポンスヘッダ内のnonceと一致する場合にのみ実行する、のような高度な制御が行えます。

一方で、既存のプロダクトでは、動いているJavaScriptがどのようにDOMを構築しているかある程度調べる必要があったり、従来使っていた外部ドメイン由来のJavaScriptを洗い出す必要があるなど、運用コストが高いです。



