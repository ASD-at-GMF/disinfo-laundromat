<script lang="ts">
	import TabsRoot from '$components/TabsRoot.svelte';
	import TabsList from '$components/TabsList.svelte';
	import TabsTrigger from '$components/TabsTrigger.svelte';
	import TabsContent from '$components/TabsContent.svelte';
	import DropdownSelect from '$components/DropdownSelect.svelte';
	import { Label, Select } from 'bits-ui';
	import type { LabeledValue } from '$types';

	const dropdown_dummy_region: LabeledValue[] = [
		{ label: 'US', value: 'US' },
		{ label: 'EU', value: 'EU' }
	];

	const dropdown_dummy_language: LabeledValue[] = [
		{ label: 'english', value: 'english' },
		{ label: 'dutch', value: 'dutch' }
	];

	interface InputData {
		region: string,
		language: string,
		[index: string]: string;
	}

	let inputData : InputData = {
		region: '',
		language: '',
	};

	function handleSelectedChange(value: string, name: string) {
		if (inputData.hasOwnProperty(name)) {
			inputData[name] = value;
		} else {
			console.error(`Unknown property: ${name}`);
		}
	}
</script>

<main class="w-100">
	<section class="grid grid-rows-2 gap-4">
		<div class=" grid grid-cols-1 gap-4 md:grid-cols-2">
			<div class="bg-blue-300">Explanation</div>
			<div class="">
				<TabsRoot value="content similarity">
					<TabsList>
						<TabsTrigger value="content similarity">Content similarity</TabsTrigger>
						<TabsTrigger value="metadata similarity">Metadata similarity</TabsTrigger>
					</TabsList>
					<TabsContent value="content similarity">
						<p>
							Search for similar content shared across the internet. Laundromat uses popular search
							engines to find related websites. Discover networks of malicious actors/websites
							collectively sharing disinformation.
						</p>
						<form>
							<Label.Root for="browsers">browsers</Label.Root>
							<DropdownSelect
								id="region_selector"
								name="region"
								selected={dropdown_dummy_region[0]}
								items={dropdown_dummy_region}
								onSelectedChange={handleSelectedChange}
							/>
							<DropdownSelect
								id="language_selector"
								name="language"
								selected={dropdown_dummy_language[0]}
								items={dropdown_dummy_language}
								onSelectedChange={handleSelectedChange}
							/>
							<button type="submit">Submit</button>
							<form></form>
						</form></TabsContent
					>
					<TabsContent value="metadata similarity">test 2 test 2</TabsContent>
				</TabsRoot>
			</div>
		</div>
		<div>
			<Label.Root for="use case list" class="bg-green-300">Label!</Label.Root>
			<ul id="use case list" class="grid grid-cols-1 gap-x-4 md:grid-cols-3">
				<li class="bg-pink-500">test1</li>
				<li class="bg-pink-500">test2</li>
				<li class="bg-pink-500">test3</li>
			</ul>
		</div>
	</section>
</main>
