# 搜索关键词模式

## 平台搜索语法

### Google Site Search

```
site:reddit.com "[product]" [keywords]
site:x.com "[product]" [keywords]
site:twitter.com "[product]" [keywords]
site:news.ycombinator.com "[product]" [keywords]
site:v2ex.com "[product]" [keywords]
site:zhihu.com "[product]" [keywords]
```

### Reddit 特定

```
# Subreddit 限定
site:reddit.com/r/[subreddit] "[product]"

# 常用子版块
/r/SaaS - SaaS 产品讨论
/r/startups - 创业相关
/r/webdev - Web 开发
/r/productivity - 效率工具
/r/selfhosted - 自托管软件
/r/degoogle - Google 替代品
/r/privacytoolsIO - 隐私工具
```

## 抱怨类关键词库

### 英文 - 强烈不满

```
[product] sucks
[product] is terrible
[product] is garbage
hate [product]
[product] is unusable
[product] nightmare
done with [product]
fed up with [product]
[product] is a joke
```

### 英文 - 中度不满

```
[product] frustrating
[product] annoying
[product] disappointing
[product] problem
[product] issue
[product] bug
[product] doesn't work
[product] broken
struggling with [product]
```

### 英文 - 功能期望

```
wish [product] could
wish [product] had
[product] should have
[product] needs to
why doesn't [product]
if only [product]
[product] is missing
[product] lacks
waiting for [product] to add
```

### 英文 - 迁移信号

```
switched from [product]
leaving [product]
moving away from [product]
replacing [product]
[product] alternative
better than [product]
instead of [product]
quit [product]
cancelled [product]
```

### 英文 - 价格相关

```
[product] too expensive
[product] overpriced
[product] not worth
[product] pricing
[product] free tier
[product] subscription
paying for [product]
[product] cost
```

### 中文 - 强烈不满

```
[产品] 垃圾
[产品] 太烂了
[产品] 坑
[产品] 真的服了
[产品] 无语
受够了 [产品]
再也不用 [产品]
[产品] 劝退
```

### 中文 - 中度不满

```
[产品] 难用
[产品] 不好用
[产品] 体验差
[产品] 有问题
[产品] bug
[产品] 卡
[产品] 慢
[产品] 闪退
```

### 中文 - 功能期望

```
希望 [产品] 能
[产品] 要是能
[产品] 什么时候支持
[产品] 缺少
[产品] 没有
为什么 [产品] 不能
[产品] 应该有
期待 [产品]
```

### 中文 - 迁移信号

```
从 [产品] 换到
弃用 [产品]
不用 [产品] 了
[产品] 替代品
比 [产品] 好用
[产品] 平替
转投
```

### 中文 - 价格相关

```
[产品] 太贵
[产品] 不值
[产品] 性价比
[产品] 收费
[产品] 涨价
[产品] 订阅
```

## 组合搜索模式

### 模式 1: 基础抱怨搜索

```
site:reddit.com "[product]" (sucks OR terrible OR hate OR frustrating)
```

### 模式 2: 功能需求搜索

```
site:reddit.com "[product]" ("wish it" OR "should have" OR "why can't" OR "is missing")
```

### 模式 3: 迁移行为搜索

```
site:reddit.com ("switched from [product]" OR "leaving [product]" OR "[product] alternative")
```

### 模式 4: 价格敏感搜索

```
site:reddit.com "[product]" (expensive OR pricing OR "not worth" OR "free tier")
```

### 模式 5: 竞品对比搜索

```
site:reddit.com "[product]" vs "[competitor]"
site:reddit.com "[product]" OR "[competitor]" (better OR worse OR comparison)
```

## 按产品类型的搜索策略

### SaaS 工具

```
# 常见抱怨
site:reddit.com "[product]" (slow OR laggy OR sync OR crash)

# 协作问题
site:reddit.com "[product]" ("team" OR "collaboration") (problem OR issue)

# 集成问题
site:reddit.com "[product]" ("integration" OR "API") (broken OR missing)
```

### 开发者工具

```
# 文档问题
site:reddit.com "[product]" (documentation OR docs) (bad OR poor OR confusing)

# 性能问题
site:reddit.com "[product]" (performance OR memory OR CPU)

# DX 问题
site:reddit.com "[product]" ("developer experience" OR DX) (frustrating)
```

### 移动应用

```
# 稳定性
site:reddit.com "[product]" (crash OR freeze OR battery)

# 更新问题
site:reddit.com "[product]" (update OR "new version") (broke OR worse)

# 权限问题
site:reddit.com "[product]" (permission OR privacy OR tracking)
```

## 时间过滤

Google 搜索时间过滤：

```
# 过去一周
site:reddit.com "[product]" sucks &tbs=qdr:w

# 过去一月
site:reddit.com "[product]" sucks &tbs=qdr:m

# 过去一年
site:reddit.com "[product]" sucks &tbs=qdr:y
```

## 高级技巧

### 1. 排除无关结果

```
site:reddit.com "[product]" frustrating -"customer support" -hiring -job
```

### 2. 精确匹配

```
site:reddit.com "[exact product name]" (用引号确保精确匹配)
```

### 3. 同时搜索多个竞品

```
site:reddit.com (Notion OR Obsidian OR Roam) (frustrating OR annoying)
```

### 4. 发现讨论帖

```
site:reddit.com "[product]" ("what do you think" OR "thoughts on" OR "experience with")
```

### 5. 发现迁移讨论

```
site:reddit.com "moved from [product]" OR "switched to [product]" reasons
```
