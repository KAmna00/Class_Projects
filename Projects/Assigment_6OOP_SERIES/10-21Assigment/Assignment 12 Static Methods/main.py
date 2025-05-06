class TemperatureConverter:
    @staticmethod
    def celsius_to_fahrenheit(celsius):
        return (celsius * 9/5) + 32

print(f"25°C = {TemperatureConverter.celsius_to_fahrenheit(25)}°F")