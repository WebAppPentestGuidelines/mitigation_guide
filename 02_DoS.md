# ファイルアップロード機能を中心としたDoS攻撃の緩和

## 1. 脆弱性の概要 / 影響

Webアプリケーションにおけるファイルアップロード機能は、多くの機能実装で不可欠である一方、DoS（Denial of Service）攻撃に脆弱となりやすい。攻撃者は巨大ファイルの送信、画像処理の計算量を悪用した資源枯渇、大量の並列リクエストなど、多様な手法でサービスの可用性を脅かすことができる。

本ドキュメントでは、ファイルアップロード機能を起点とするDoS攻撃の脅威モデルを整理し、ネットワーク層からアプリケーション層、処理層、アーキテクチャ層に至る多層防御の考え方に基づき、緩和策をまとめる。

## 2. 脅威モデル

ファイルアップロード機能に関連するDoS攻撃は、主に以下の4つのベクトルに分類できる。

### 2.1 帯域・セッションの枯渇

大量のHTTPリクエストを並列送信し、Webサーバーの同時接続数やセッションプールを飽和させる。ファイルアップロードのエンドポイントは、リクエストボディが大きくなるため、通常のAPIエンドポイントよりも帯域の消費効率が高い。

### 2.2 ストレージの枯渇

巨大なファイルを繰り返しアップロードし、サーバーのディスク容量を圧迫する。ストレージが枯渇すると、ログの書き込みやデータベース操作にも影響が波及し、システム全体の機能不全を引き起こす。

### 2.3 CPU・メモリの枯渇（Decompression Bomb / Pixel Flood）

ファイルサイズは小さいが、展開後に膨大なリソースを消費するファイルを送信する。代表的な手法として以下がある。

- **Decompression Bomb（展開爆弾）**: 圧縮ファイルや画像のヘッダ情報を細工し、展開時に数十GBのメモリを要求する。PNGのIHDRチャンクに異常なピクセル数（例：50,000 x 50,000ピクセル）を宣言するといった例が考えられる。
- **Pixel Flood攻撃**: JPEGファイルのヘッダに巨大な画像寸法を定義し、画像変換ライブラリが全ピクセルをメモリに展開しようとする際にメモリを溢れさせる。

### 2.4 処理遅延（Slow Processing）

サーバー側の画像変換・リサイズ処理の計算量を悪用する。ファイルサイズの制限だけでは防御できず、ピクセル数、フレーム数、色深度など処理の計算量に直結するパラメータの制御が必要となる。

## 3. 多層防御による緩和・対策

### 3.1 ネットワーク層の防御

#### 3.1.1 WAF（Web Application Firewall）の活用

WAFはアプリケーション層の攻撃を検知・遮断する最前線の防御である。主要なクラウドWAFサービスは、以下の機能を提供する。

| 機能 | 説明 |
|------|------|
| IPレピュテーション | 既知のボットネットIPからのアクセスを遮断 |
| レートベースルール | 一定期間内のリクエスト数超過で自動遮断 |
| リクエストサイズ制限 | 異常に大きいリクエストボディを遮断 |
| Bot Control | 機械学習によるボット判定とチャレンジ発行 |

#### 3.1.2 IPブラックリストとレピュテーションフィルタリング

ボットネットの送信元IPは、脅威インテリジェンスフィードを通じて共有される。例えば、AWS WAFのAmazonIpReputationListマネージドルールグループには、DDoS活動に積極的に関与しているIPを検査する`AWSManagedIPDDoSList`ルールが含まれている。

ただし、IPアドレスベースの遮断には後述するCGNAT問題に注意が必要である。

### 3.2 アプリケーション層の防御

#### 3.2.1 レート制限の設計

レート制限は、DoS対策の中核をなす機能である。効果的なレート制限は、複数の識別子を組み合わせて実装する必要がある。

| 識別子 | 適用場面 | 利点 | 制約 |
|--------|----------|------|------|
| IPアドレス | 全エンドポイント | 実装が容易 | CGNAT環境で正規ユーザーに影響する可能性がある |
| 認証済みユーザーID | 認証必須エンドポイント | 精密な制御 | 未認証エンドポイントには適用不可 |
| APIキー | API提供サービス | クライアント単位の制御 | キーの発行方法によっては同様のリスクが発生 |

**CGNAT問題**: モバイル回線や一部のISPでは、CGNAT（Carrier-Grade NAT）により多数のユーザーが単一のパブリックIPアドレスを共有する。これを考慮した制御をしなければ、正規ユーザーの誤判定によって、攻撃者のDoS攻撃の目的が意図せず達成されてしまう。

この問題への対処として、以下のアプローチが推奨される。
- IPアドレス単体ではなく、セッショントークンやブラウザフィンガープリントとの複合判定を行う
- CGNAT IPの検出を行い、検出時にはレート制限の閾値を動的に調整する
- Cloudflare等のCDN/WAFが提供するBot Scoreを併用し、人間のトラフィックとボットトラフィックを区別する

#### 3.2.2 リクエストサイズの上限設定

リクエストボディサイズに上限を設けることは、基本的かつ効果的な対策である。この制限はWebサーバーレベルとアプリケーションレベルの両方で設定することが推奨される。

**Webサーバーレベルの制限**:
- **Nginx**: `client_max_body_size`ディレクティブでHTTPリクエスト全体のサイズを制限する。デフォルトは1MBであり、ファイルアップロードを許容する場合は適切な値に変更する必要がある
- **Apache**: `LimitRequestBody`ディレクティブで同様の制限を行う

Webサーバーレベルで制限をかけることにより、巨大なリクエストボディがアプリケーションに到達する前に遮断でき、アプリケーションサーバーのリソース消費を未然に防止できる。

**アプリケーションレベルの制限**:
リクエストのペイロードごとに次のような設定例が考えられる。

- **JSONリクエスト**: 最大ボディサイズを業務要件に応じて設定
- **ファイルアップロード**: 許容する最大ファイルサイズを明示的に制限
- **マルチパートリクエスト**: パート数の上限を設定

また、バリデーションが逆にDoS攻撃に繋がることを防ぐため、リソースコストの低いバリデーションを先に実行する考え方も必要となる。リクエストサイズの検証は、ファイル内容の解析よりも先に行うべきである。

#### 3.2.3 CAPTCHA・チャレンジ

ボットによる大量リクエストの排除に有効な手段としてCAPTCHAがある。これは、ボットには解くことが難しいパズル問題やユーザーの行動の解析などによって、操作しているユーザーが自動化されたボットかどうかを区別する認証システムである。

ただし、ユーザビリティを損ねる場合も多いため、例えば繰り返し実行された場合にのみCAPTCHAを挿入するなどして影響を抑えて導入することも考えられる。


#### 3.2.4 ユーザー単位のアップロード回数制限

認証済み環境であれば、ユーザーごとにアップロード回数や間隔に制限を設けることが有効である。ファイルサイズの制限内であっても、大量の並列アップロードによるリソース飽和を防止する。

#### 3.2.5 待機室

急激なトラフィック増加時に、ユーザーを仮想的な待機室に誘導し、サーバーの同時接続数を平準化することができる。

### 3.3 ファイル処理層の防御

#### 3.3.1 ファイルサイズ制限

ファイルサイズはメモリやディスクなどのリソース消費に直接的な関係があることが多い。

ただし、ファイルサイズが小さくても、Decompression BombやPixel Floodにより展開後のリソース消費が膨大となるケースがある点は注意が必要である。

#### 3.3.2 ファイル形式の厳密な検証

ファイル形式によっては外部のリソース参照などの特殊な処理が実行され、DoS攻撃だけではなく、脆弱性の悪用に繋がる場合があり、特定のファイル形式のみ許可することで対策に繋がる。

1. **拡張子の許可リスト方式**: 業務上必要な拡張子のみを許可し、それ以外は拒否する
2. **Content-Typeヘッダの検証**: クライアントから送信されるContent-Typeは容易に偽装可能であるため、補助的なチェックとしてのみ利用する
3. **マジックバイト（ファイルシグネチャ）検証**: ファイル先頭のバイト列を検査し、宣言されたファイル形式と実際の内容が一致するか確認する。これがファイル形式検証の中で最も信頼性が高い

重要なのは、リクエストヘッダやファイル名から得られる情報を信頼せず、ファイルの実体を検証することである。

#### 3.3.3 画像固有のリソース制限

特に画像処理においては、ファイルサイズだけでなく、処理の計算量に直結するパラメータの制限が必要である。

| パラメータ | 制限の目的 | 想定される攻撃 |
|-----------|-----------|--------------|
| ピクセル数（幅 x 高さ） | メモリ展開量の制限 | Pixel Flood、Decompression Bomb |
| フレーム数 | アニメーション画像の処理量制限 | GIF/APNG Bomb |
| 色深度（ビット深度） | チャネルあたりのデータ量制限 | 高ビット深度画像による処理負荷 |
| 解像度（DPI） | 印刷向け高解像度画像の制限 | 不必要な高解像度による負荷 |

例えばImageMagickを使用する場合、`policy.xml`によってリソース制限が可能である。

次のような制限が可能である。

| リソース | 説明 |
|----------|------|
| width | 処理可能な最大画像幅 |
| height | 処理可能な最大画像高さ |
| area | メモリ保持する最大ピクセル数。超過分はディスクキャッシュ |
| memory | ヒープから割り当て可能な最大メモリ |
| map | メモリマップドI/Oの最大サイズ |
| disk | 一時ファイルの最大ディスク使用量 |
| time | 単一処理の最大実行時間 |
| thread | 並列処理のスレッド数 |

これらを用いて、下記のような設定ができる。

```xml
<policymap>
  <!-- リソース制限 -->
  <policy domain="resource" name="memory" value="256MiB"/>
  <policy domain="resource" name="map" value="512MiB"/>
  <policy domain="resource" name="width" value="8KP"/>
  <policy domain="resource" name="height" value="8KP"/>
  <policy domain="resource" name="area" value="16KP"/>
  <policy domain="resource" name="disk" value="1GiB"/>
  <policy domain="resource" name="time" value="120"/>
  <policy domain="resource" name="thread" value="2"/>
  <policy domain="resource" name="list-length" value="32"/>

  <!-- モジュール制限: 全モジュールを無効化した上で、安全な形式のみ許可 -->
  <policy domain="module" rights="none" pattern="*" />
  <policy domain="module" rights="read|write" pattern="{GIF,JPEG,PNG,WEBP}" />

  <!-- 危険なコーダーの明示的な無効化 -->
  <policy domain="coder" rights="none" pattern="PDF" />
  <policy domain="coder" rights="none" pattern="PS" />
  <policy domain="coder" rights="none" pattern="EPS" />
  <policy domain="coder" rights="none" pattern="XPS" />
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="MSL" />
  <policy domain="coder" rights="none" pattern="EPHEMERAL" />
  <policy domain="coder" rights="none" pattern="HTTP" />
  <policy domain="coder" rights="none" pattern="HTTPS" />

  <!-- @ファイル名によるファイル読み込みの禁止 -->
  <policy domain="path" rights="none" pattern="@*" />
</policymap>
```

#### 3.3.4 タイムアウトとプロセス制御

画像変換処理には明示的なタイムアウトを設定し、制限時間内に完了しないプロセスを強制終了（kill）する仕組みが必要である。これにより、Slow Processing攻撃の影響を限定的にできる。

### 3.4 アーキテクチャ層の防御

#### 3.4.1 非同期処理とキューイング

ファイルアップロードのリクエスト処理とファイルの変換処理を分離し、非同期に実行する設計は、DoS耐性を大幅に向上させる。

**基本的な設計パターン**:
1. Webサーバーはファイルを受け取り、メッセージキューにジョブを投入する
2. Webサーバーはクライアントに即座にレスポンスを返す
3. 別のワーカープロセス（または別サーバー）がキューからジョブを取り出し、ファイル処理を実行する

この設計により、ファイル処理の負荷がWebサーバーに直接影響することを防止し、処理キューの消費速度を制御することで、システム全体の安定性を維持できる。

#### 3.4.2 処理サーバーの分離

Webサーバーとファイル処理サーバーを物理的または論理的に分離することで、ファイル処理を起因とする障害がWeb APIの応答性に影響することを防ぐ。

- **エンドポイント単位のルーティング**: リバースプロキシやAPIゲートウェイを用いて、重い処理を伴うエンドポイントを専用のバックエンドサーバーに振り分ける
- **リソースの独立管理**: 処理サーバーのCPU・メモリが枯渇しても、Webサーバーの通常のAPI応答には影響しない構成とする
- **サーバーレス/FaaS（Function as a Service）の活用**: ファイル変換処理をサーバーレス関数として実装することで、処理単位でのリソース分離とスケーリングを実現する。各関数の実行時間・メモリに上限を設定できるため、DoSの影響範囲を限定しやすい


---

## 4. 出典・参考文献

- OWASP Denial of Service Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

- OWASP File Upload Cheat Sheet  
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

- OWASP Unrestricted File Upload  
  https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

- ImageMagick Security Policy（公式ドキュメント）  
  https://imagemagick.org/script/security-policy.php

- Doyensec ImageMagick Security Policy Evaluator  
  https://imagemagick-secevaluator.doyensec.com/

- Doyensec Blog: ImageMagick Security Policy Evaluator（2023-01-10）  
  https://blog.doyensec.com/2023/01/10/imagemagick-security-policy-evaluator.html

- AWS WAF: Three Most Important Rate-Based Rules（2025-05-05更新）  
  https://aws.amazon.com/blogs/security/three-most-important-aws-waf-rate-based-rules/

- AWS Best Practices for DDoS Resiliency  
  https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/

- Cloudflare Blog: Introducing AI Crawl Control（2025-08-28）  
  https://blog.cloudflare.com/introducing-ai-crawl-control/

- Cloudflare Blog: Introducing Pay Per Crawl  
  https://blog.cloudflare.com/introducing-pay-per-crawl/

- The Register: ISPs More Likely to Throttle CGNAT Traffic（2025-11-03）  
  https://www.theregister.com/2025/11/03/cloudflare_cgnat_bias_research/

- NIST SP 800-189 Rev.1: Resilient Interdomain Traffic Exchange: BGP Security and DDoS Mitigation  
  https://csrc.nist.gov/pubs/sp/800/189/final

- CarrierWave Wiki: Pixel Flood Attack  
  https://github.com/carrierwaveuploader/carrierwave/wiki/Denial-of-service-vulnerability-with-maliciously-crafted-JPEGs--(pixel-flood-attack)

- Cloudflare Rate Limiting Best Practices  
  https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/

- ImageTragick（CVE-2016-3714）  
  https://imagetragick.com/
