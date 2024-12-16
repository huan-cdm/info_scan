from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import sys



# 设置Chrome选项
chrome_options = Options()
chrome_options.add_argument("--no-sandbox")  # 允许Chrome在没有沙箱环境的情况下运行
chrome_options.add_argument("--disable-dev-shm-usage")  # 避免使用/dev/shm
chrome_options.add_argument("--disable-gpu")  # 禁用GPU硬件加速
chrome_options.add_argument("--headless")  # 无头模式
chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
cookies = {
    'Cookie':'_ga=GA1.1.1110716225.1734258983; Hm_lvt_b420ace1c5d07333ada549fcfc62c11b=1734258983; HMACCOUNT=B54EE7741933AFAC; PHPSESSID=vuupkm484tip0balp6l2l0bdon; ip=101.198.192.116; token=6da8780405ecd96eb4df7d87e327f601; recognition=6c54daf836522d41eb2327eec2c4d647; Hm_lpvt_b420ace1c5d07333ada549fcfc62c11b=1734259394; _ga_CWE059XRGV=GS1.1.1734258982.1.1.1734259398.0.0.0'
}
chrome_options.add_argument(cookies)

# 初始化浏览器
driver = webdriver.Chrome(options=chrome_options)
# 打开目标网站
driver.get("https://www.icpapi.com/")

# 设置显式等待
wait = WebDriverWait(driver, 20)  # 等待最长20秒

# 定位到输入框，这里需要替换"input_id"为实际的输入框ID
input_box = driver.find_element(By.ID, "searchInput")

# 传入域名
part = sys.argv[1]
input_box.send_keys(part)

# 定位到按钮并点击
button = wait.until(EC.element_to_be_clickable((By.XPATH, "/html/body/div/div[2]/div[2]/div[1]/span/button")))
button.click()

# 等待查询结果的链接元素加载完成
result_link_xpath = "/html/body/div/div[3]/div/div/div/table/tbody/tr[4]/td[2]/a"
result_link = wait.until(EC.presence_of_element_located((By.XPATH, result_link_xpath)))

# 打印链接的文本内容
print(result_link.text)


# 完成操作后，关闭浏览器（根据需要决定是否在这里关闭）
driver.quit()