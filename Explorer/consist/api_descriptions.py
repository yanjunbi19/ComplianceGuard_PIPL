def get_api_descriptions(sens_api):
    api_des_dict = {}

    try:
        with open('monitoring/permissions_api.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and '|' in line:
                    api_part, description = line.split('|', 1)
                    api_des_dict[api_part.strip()] = ['', description.strip()]
    except FileNotFoundError:
        print("API描述文件未找到: monitoring/permissions_api.txt")
        return ''
    except Exception as e:
        print(f"读取API描述文件时出错: {e}")
        return ''

    if sens_api in api_des_dict:
        api_des_list = api_des_dict[sens_api]
        self_description, comment_description = api_des_list[0], api_des_list[1]
        return self_description + ' ' + comment_description
    else:
        class_name, function_name = sens_api.rsplit('.', 1)
        for item in api_des_dict.keys():
            if class_name in item and function_name in item:
                api_des_list = api_des_dict[item]
                self_description, comment_description = api_des_list[0], api_des_list[1]
                return self_description + ' ' + comment_description
    return ''
