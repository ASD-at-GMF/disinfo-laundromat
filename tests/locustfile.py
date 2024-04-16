from locust import FastHttpUser, HttpUser, between, task


class WebUser(FastHttpUser):
    wait_time = between(5, 15)

    def check_response_time(self, response, max_time_ms=10000):
        if response.request_meta["response_time"] > max_time_ms:
            response.failure(f"Request exceeded max response time of {max_time_ms:,}ms")

    @task
    def homepage(self):
        self.client.get("/")

    @task(3)
    def content_search(self):
        data = {
            "contentToSearch": "https://www.rt.com/news/594935-us-uk-ukraine-moscow-terrorism/",
            "country": "us",
            "language": "en",
        }

        with self.client.post("/content-search", data, catch_response=True) as response:
            self.check_response_time(response)

    @task(3)
    def url_search(self):
        data = {
            "url": "https://actualidad.rt.com,https://actualidad-rt.com,https://esrt.online,https://esrt.press",
            "run_urlscan": "no",
            "internal_only": "option1",
        }

        with self.client.post("/url-search", data, catch_response=True) as response:
            self.check_response_time(response, max_time_ms=20000)
