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

# 设置ChromeDriver路径
s = Service('/usr/bin/chromedriver')  # 确保这里的路径是ChromeDriver的实际路径

# 初始化WebDriver
# driver = webdriver.Chrome(service=s, options=chrome_options)

# 初始化浏览器
driver = webdriver.Chrome(options=chrome_options)
# 打开目标网站
driver.get("https://www.icpapi.com/")

# 设置显式等待
wait = WebDriverWait(driver, 20)  # 等待最长20秒

# 定位到输入框并输入字符串"test"
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