import launch
import launch_ros.actions
from launch.actions import DeclareLaunchArgument, OpaqueFunction
from launch.substitutions import LaunchConfiguration
from pathlib import Path
import re


launch_args = [
    DeclareLaunchArgument(name='certs_path', description='IoT Certificates path'),
]

def get_certs_path(context):
    certs_path_arg = LaunchConfiguration("certs_path").perform(context)
    certs_path = Path(certs_path_arg)
    all_configs = certs_path.glob("iot_config_*.json")
    name_regex = re.compile(".*iot_config_(.*)\.json")

    nodes = []
    for config in all_configs:
        print(config)
        if match := name_regex.search(str(config)):
            robot_name = match.group(1)
            shadow_name = f"{robot_name}-shadow"
            print(str(config))
            print(shadow_name)

            nodes += [
                launch_ros.actions.Node(
                    namespace=robot_name,
                    package="iot_shadow_service",
                    executable="digit_generator",
                    name="digit_generator",
                ),
                launch_ros.actions.Node(
                    namespace=robot_name,
                    package="iot_shadow_service",
                    executable="safe_cracker",
                    name="safe_cracker",
                ),
                launch_ros.actions.Node(
                    namespace=robot_name,
                    package="iot_shadow_service",
                    executable="iot_shadow_node",
                    name=f"shadow_node",
                    parameters=[{
                        "path_for_config": str(config),
                        "shadow_name": shadow_name,
                    }],
                )
            ]

    return nodes

def generate_launch_description():
    opfunc = OpaqueFunction(function=get_certs_path)
    ld = launch.LaunchDescription()
    ld.add_action(opfunc)
    return ld
