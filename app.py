import ipaddress
import math
import random
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
  """يعرض صفحة الـ HTML الرئيسية (يُفضل حفظ index.html داخل مجلد باسم templates)"""
  return render_template("index.html")


# ==========================================
# 1. Basic IP Analyzer Engine
# ==========================================
@app.route("/api/analyze-basic", methods=["POST"])
def analyze_basic():
  data = request.json or {}
  ip_str = data.get("ip", "192.168.1.50").strip()
  mask_str = data.get("mask", "/24").strip()

  try:
    if not mask_str.startswith("/"):
      network_input = f"{ip_str}/{mask_str}"
    else:
      network_input = f"{ip_str}{mask_str}"

    net = ipaddress.ip_network(network_input, strict=False)
    ip_obj = ipaddress.ip_address(ip_str)

    # تحويل الأوكتيتات إلى ثنائي (32 بت ممتدة)
    binary_ip = " . ".join([f"{int(oct):08b}" for oct in ip_obj.packed])

    # تحديد الكلاس الأساسي (Classful Classification)
    first_octet = int(ip_str.split(".")[0])
    if 1 <= first_octet <= 126:
      ip_class = "Class A"
    elif 128 <= first_octet <= 191:
      ip_class = "Class B"
    elif 192 <= first_octet <= 223:
      ip_class = "Class C"
    elif 224 <= first_octet <= 239:
      ip_class = "Class D (Multicast)"
    else:
      ip_class = "Class E (Experimental/Reserved)"

    hosts = list(net.hosts())
    first_usable = str(hosts[0]) if hosts else str(net.network_address)
    last_usable = str(hosts[-1]) if hosts else str(net.broadcast_address)

    return jsonify({
        "status": "success",
        "ip": ip_str,
        "netmask": str(net.netmask),
        "cidr": f"/{net.prefixlen}",
        "network_id": str(net.network_address),
        "broadcast_address": str(net.broadcast_address),
        "first_usable": first_usable,
        "last_usable": last_usable,
        "total_hosts": net.num_addresses,
        "usable_hosts": (
            max(0, net.num_addresses - 2) if net.num_addresses > 2 else 1
        ),
        "ip_class": ip_class,
        "is_private": ip_obj.is_private,
        "binary_format": binary_ip,
    })
  except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400


# ==========================================
# 2. FLSM (Fixed Length Subnet Masking) Engine
# ==========================================
@app.route("/api/solve-flsm", methods=["POST"])
def solve_flsm():
  data = request.json or {}
  base_input = data.get("ip", "192.168.1.0/24").strip()
  split_type = data.get("type", "subnets")  # 'subnets' or 'hosts'
  count = int(data.get("count", 4))

  try:
    net = ipaddress.ip_network(base_input, strict=False)

    if split_type == "subnets":
      # حساب عدد بتات الشبكة المستعارة n حيث 2^n >= count
      n = math.ceil(math.log2(count)) if count > 1 else 0
      new_prefix = net.prefixlen + n
      if new_prefix > 32:
        return (
            jsonify({
                "status": "error",
                "message": (
                    "Requested number of subnets exceeds 32-bit IPv4 limit."
                ),
            }),
            400,
        )
      subnets = list(net.subnets(new_prefix=new_prefix))[:count]
    else:
      # حساب بدلالة عدد الأجهزة المطلوبة h حيث 2^h - 2 >= count
      h = 0
      while (2**h - 2) < count:
        h += 1
      new_prefix = 32 - h
      if new_prefix < net.prefixlen:
        return (
            jsonify({
                "status": "error",
                "message": "Requested hosts exceed base network capacity.",
            }),
            400,
        )
      subnets = list(net.subnets(new_prefix=new_prefix))

    results = []
    for idx, sub in enumerate(subnets):
      hosts = list(sub.hosts())
      first_host = str(hosts[0]) if hosts else "N/A"
      last_host = str(hosts[-1]) if hosts else "N/A"
      results.append({
          "id": idx + 1,
          "network_id": str(sub.network_address),
          "cidr": f"/{sub.prefixlen}",
          "first_usable": first_host,
          "last_usable": last_host,
          "broadcast": str(sub.broadcast_address),
          "usable_hosts": max(0, sub.num_addresses - 2),
      })

    return jsonify({
        "status": "success",
        "base_network": str(net),
        "new_netmask": str(subnets[0].netmask) if subnets else "",
        "subnets": results,
    })
  except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400


# ==========================================
# 3. VLSM (Variable Length Subnet Masking) Engine
# ==========================================
@app.route("/api/solve-vlsm", methods=["POST"])
def solve_vlsm():
  data = request.json or {}
  base_ip = data.get("base_ip", "192.168.1.0/24").strip()
  departments = data.get("departments", [])

  try:
    base_net = ipaddress.ip_network(base_ip, strict=False)

    # 1. الفرز التنازلي للأقسام حسب عدد الأجهزة (أهم شرط في VLSM لمنع التداخل)
    valid_depts = []
    for d in departments:
      try:
        valid_depts.append({
            "name": d.get("name", "Department").strip() or "Department",
            "hosts": int(d.get("hosts", 0)),
        })
      except (ValueError, TypeError):
        continue

    sorted_depts = sorted(valid_depts, key=lambda x: x["hosts"], reverse=True)

    if not sorted_depts:
      return (
          jsonify(
              {"status": "error", "message": "No valid departments provided."}
          ),
          400,
      )

    allocation_results = []
    current_addr = int(base_net.network_address)
    max_addr = int(base_net.broadcast_address)

    for dept in sorted_depts:
      dept_name = dept["name"]
      hosts_needed = dept["hosts"]

      # حساب عدد بتات الأجهزة المطلوبة h
      h = 0
      while (2**h - 2) < max(hosts_needed, 2):
        h += 1

      prefix = 32 - h
      subnet_size = 2**h

      # التأكد من التحرير على حدود العنوان (Subnet Alignment)
      if current_addr % subnet_size != 0:
        current_addr = ((current_addr // subnet_size) + 1) * subnet_size

      # التحقق من عدم تجاوز حدود الشبكة الكلية
      if (current_addr + subnet_size - 1) > max_addr:
        return (
            jsonify({
                "status": "error",
                "message": (
                    f"Insufficient IP address space for department"
                    f" '{dept_name}' ({hosts_needed} hosts required)."
                ),
            }),
            400,
        )

      allocated_net = ipaddress.ip_network(
          f"{ipaddress.ip_address(current_addr)}/{prefix}"
      )
      hosts = list(allocated_net.hosts())

      allocation_results.append({
          "department": dept_name,
          "hosts_requested": hosts_needed,
          "allocated_hosts": (2**h - 2),
          "cidr": f"/{prefix}",
          "network_id": str(allocated_net.network_address),
          "first_usable": (
              str(hosts[0]) if hosts else str(allocated_net.network_address)
          ),
          "last_usable": (
              str(hosts[-1]) if hosts else str(allocated_net.broadcast_address)
          ),
          "broadcast": str(allocated_net.broadcast_address),
      })

      # الانقال للعنوان المباشر بعد Broadcast الشبكة الحالية
      current_addr += subnet_size

    return jsonify({
        "status": "success",
        "base_network": str(base_net),
        "allocations": allocation_results,
    })
  except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400


# ==========================================
# 4. Reverse IP Range Checker Engine
# ==========================================
@app.route("/api/solve-reverse", methods=["POST"])
def solve_reverse():
  data = request.json or {}
  target_ip_str = data.get("target_ip", "").strip()
  net_input_str = data.get("net_ip", "").strip()

  try:
    ip_obj = ipaddress.ip_address(target_ip_str)
    net_obj = ipaddress.ip_network(net_input_str, strict=False)

    belongs = ip_obj in net_obj

    # تحديد موقع الجهاز بالضبط في النطاق
    hosts = list(net_obj.hosts())
    host_position = "N/A"
    if belongs and hosts:
      if ip_obj == net_obj.network_address:
        host_position = "Network ID (Unusable for hosts)"
      elif ip_obj == net_obj.broadcast_address:
        host_position = "Broadcast ID (Unusable for hosts)"
      else:
        host_index = int(ip_obj) - int(net_obj.network_address)
        host_position = f"Host #{host_index} in range"

    return jsonify({
        "status": "success",
        "belongs": belongs,
        "target_ip": target_ip_str,
        "network": str(net_obj),
        "network_id": str(net_obj.network_address),
        "broadcast": str(net_obj.broadcast_address),
        "host_position": host_position,
    })
  except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400


# ==========================================
# 5. Route Summarization (Supernetting) Engine
# ==========================================
@app.route("/api/solve-supernet", methods=["POST"])
def solve_supernet():
  data = request.json or {}
  ips_text = data.get("ips", "")

  try:
    lines = [line.strip() for line in ips_text.split("\n") if line.strip()]
    if not lines:
      return (
          jsonify(
              {"status": "error", "message": "No valid networks provided."}
          ),
          400,
      )

    networks = [ipaddress.ip_network(net, strict=False) for net in lines]

    # تجميع الشبكات
    collapsed = list(ipaddress.collapse_addresses(networks))
    summary_net = collapsed[0] if collapsed else networks[0]

    # حساب Wildcard Mask المخصص لقوائم التحكم بالوصول ACL
    netmask_int = int(summary_net.netmask)
    wildcard_int = netmask_int ^ 0xFFFFFFFF
    wildcard_mask = str(ipaddress.ip_address(wildcard_int))

    return jsonify({
        "status": "success",
        "summary_route": str(summary_net),
        "netmask": str(summary_net.netmask),
        "wildcard_mask": wildcard_mask,
        "total_networks_aggregated": len(networks),
    })
  except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400


# ==========================================
# 6. Quiz Scenario Generator Engine
# ==========================================
@app.route("/api/generate-quiz", methods=["POST"])
def generate_quiz():
  data = request.json or {}
  level = data.get("level", "medium")

  questions_pool = {
      "easy": [
          {
              "q": "What is the default subnet mask for a Class C IP address?",
              "options": [
                  "255.0.0.0",
                  "255.255.0.0",
                  "255.255.255.0",
                  "255.255.255.224",
              ],
              "ans": "255.255.255.0",
          },
          {
              "q": "How many total IP addresses are in a /24 network block?",
              "options": ["128", "256", "512", "1024"],
              "ans": "256",
          },
      ],
      "medium": [
          {
              "q": (
                  "Given the network 172.16.0.0/16, if you borrow 6 bits for"
                  " subnetting, what is the new CIDR mask?"
              ),
              "options": ["/20", "/22", "/24", "/26"],
              "ans": "/22",
          },
          {
              "q": (
                  "What is the usable host capacity for a subnet with a /27"
                  " mask?"
              ),
              "options": ["14", "30", "62", "126"],
              "ans": "30",
          },
      ],
      "hard": [
          {
              "q": (
                  "In a VLSM design, what prefix length is required for a WAN"
                  " point-to-point link requiring only 2 usable IPs?"
              ),
              "options": ["/28", "/29", "/30", "/31"],
              "ans": "/30",
          },
          {
              "q": (
                  "What is the broadcast address for the subnet"
                  " 192.168.1.64/26?"
              ),
              "options": [
                  "192.168.1.127",
                  "192.168.1.95",
                  "192.168.1.255",
                  "192.168.1.63",
              ],
              "ans": "192.168.1.127",
          },
      ],
      "expert": [
          {
              "q": (
                  "What is the ACL Wildcard Mask for a network with Subnet Mask"
                  " 255.255.240.0?"
              ),
              "options": ["0.0.15.255", "0.0.31.255", "0.0.7.255", "0.0.255.255"],
              "ans": "0.0.15.255",
          },
          {
              "q": (
                  "Does the host IP 10.1.5.130/22 belong to the subnet"
                  " 10.1.4.0/22?"
              ),
              "options": [
                  "Yes, it falls inside 10.1.4.1 - 10.1.7.254",
                  "No, it belongs to 10.1.5.0/24",
                  "No, 10.1.4.0/22 ends at 10.1.4.255",
                  "Invalid IP range",
              ],
              "ans": "Yes, it falls inside 10.1.4.1 - 10.1.7.254",
          },
      ],
  }

  pool = questions_pool.get(level, questions_pool["medium"])
  selected_q = random.choice(pool)

  return jsonify({"status": "success", "level": level, "question": selected_q})


if __name__ == "__main__":
  # تشغيل خادم بايثون المحلي على المنفذ 5000
  app.run(debug=True, port=5000)