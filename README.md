# 横向移动取证

同一凭据在几分钟内出现在多台主机，事后还有提权动作。

```
logs/auth.log   850 行（合成，含 2 起真实事件）
labels.json     2 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 检测逻辑

`detector/detector.py` 做关联检测，输出 `findings` + `needs_review`：

- `lateral_movement`：同一账号在 10 分钟内从**两个都从未用过的源 IP** 登录，
  且随后 15 分钟内伴随提权（sudo 至 root）或 root 从同一新 IP 登录。
  正常轮换发生在已知跳板机集合内、且无后续提权，被抑制。
- `privilege_escalation`：sudo 起 root shell 后 5 分钟内，root 从该账号
  此前会话使用过的同一源 IP 登录。
- `needs_review`：日志本身无法判定的相似流量（少量失败后成功、被拒的
  敏感路径探测），每条写明缺哪类资产信息（CMDB、VPN/DHCP 租约、
  扫描器白名单等）。

每条 finding 含 `rule`、`first_seen`/`last_seen` 时间窗口、`entities`
（users/ips/hosts）和按序的 `evidence` 事件链（带行号）。

## 标注事件

| kind | 说明 |
|---|---|
| `lateral_movement` | 同一凭据跨主机横向移动 |
| `privilege_escalation` | 提权 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
